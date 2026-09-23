//! Durable broker idempotence journal persistence.
//!
//! Extracted verbatim from `ledger.rs`: the `BrokerLedger` state, its bounded
//! append/commit persistence and its reservation admission keep the exact
//! durable schema, ordering and error semantics.

#[allow(clippy::wildcard_imports)]
use super::super::*;

use super::ledger_binding::JobBinding;
use super::ledger_records::{
    LaunchIdentity, LedgerRecord, LedgerState, LifecycleRecord, parse_records,
    same_process_binding, sync_directory, validate_protected_ledger_path,
};

/// Durable idempotence journal. A pending record is written and synced before
/// StartTransientUnit. If the broker dies after the effect, a later broker can
/// inspect the exact unit; an inactive or missing unit is never relaunched from
/// an old nonce.
#[derive(Debug)]
pub struct BrokerLedger {
    path: Option<PathBuf>,
    pub(super) records: BTreeMap<BrokerRequest, LedgerRecord>,
    poisoned: bool,
    #[cfg(test)]
    append_failure: Option<AppendFailure>,
    #[cfg(test)]
    reject_next_commit: bool,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppendFailure {
    PartialWrite,
    Sync,
}

impl BrokerLedger {
    /// Only committed identities can bind inherited containment. Pending
    /// reservations and terminal records never authorize process adoption.
    pub(in crate::platform::linux_broker) fn recoverable_receipts(
        &self,
        policy: &BrokerPolicy,
    ) -> BrokerResult<Vec<LaunchReceipt>> {
        self.ensure_healthy()?;
        let mut receipts = Vec::new();
        for (request, record) in &self.records {
            if !matches!(
                record.state,
                LedgerState::Committed | LedgerState::StopPending
            ) {
                continue;
            }
            let launch_policy = policy.component(request.component)?;
            let unit = unit_name(request);
            match self.lifecycle_record(request, &unit, launch_policy)? {
                Some(
                    LifecycleRecord::Committed(receipt) | LifecycleRecord::StopPending(receipt),
                ) => {
                    verify_receipt_identity(&receipt, request, &unit, launch_policy)?;
                    receipts.push(receipt);
                }
                _ => {
                    return Err(BrokerError::Conflict(
                        "recovery ledger state changed".to_owned(),
                    ));
                }
            }
        }
        Ok(receipts)
    }

    pub fn memory() -> Self {
        Self {
            path: None,
            records: BTreeMap::new(),
            poisoned: false,
            #[cfg(test)]
            append_failure: None,
            #[cfg(test)]
            reject_next_commit: false,
        }
    }

    pub fn open(path: impl Into<PathBuf>) -> BrokerResult<Self> {
        let path = path.into();
        validate_protected_ledger_path(&path)?;
        let mut ledger = Self {
            path: Some(path.clone()),
            records: BTreeMap::new(),
            poisoned: false,
            #[cfg(test)]
            append_failure: None,
            #[cfg(test)]
            reject_next_commit: false,
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(io_error(error)),
        };
        let Some(metadata) = metadata else {
            return Err(BrokerError::Unavailable(
                "broker ledger is missing; initialize it explicitly before opening".to_owned(),
            ));
        };
        if !metadata.is_file()
            || !is_protected_owner(metadata.uid())
            || metadata.mode() & 0o077 != 0
        {
            return Err(BrokerError::Invalid(
                "broker ledger must be a root-owned mode-0600 regular file".to_owned(),
            ));
        }
        let bytes = read_bounded_file(&path, MAX_LEDGER_BYTES, "broker ledger")?;
        ledger.records = parse_records(&bytes)?;
        Ok(ledger)
    }

    /// Explicitly create a new empty ledger. Opening a missing path never
    /// initializes state because that would make an active unit adoptable
    /// without durable pre-launch history.
    pub fn init(path: impl Into<PathBuf>) -> BrokerResult<Self> {
        let path = path.into();
        let parent = path
            .parent()
            .ok_or_else(|| BrokerError::Invalid("broker ledger has no parent".to_owned()))?;
        validate_protected_directory(parent, "broker ledger directory")?;
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(BrokerError::Conflict(
                    "broker ledger already exists; refusing to replace it".to_owned(),
                ));
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(error)),
        }
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true).mode(0o600);
        let file = options.open(&path).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || !is_protected_owner(metadata.uid())
            || metadata.mode() & 0o077 != 0
        {
            return Err(BrokerError::Unauthorized(
                "broker ledger initialization produced unsafe ownership or mode".to_owned(),
            ));
        }
        file.sync_all().map_err(io_error)?;
        sync_directory(parent)?;
        Self::open(path)
    }

    pub(in crate::platform::linux_broker) fn contains(&self, request: &BrokerRequest) -> bool {
        self.records.contains_key(request)
    }

    pub(in crate::platform::linux_broker) fn lifecycle_record(
        &self,
        request: &BrokerRequest,
        unit: &str,
        policy: &LaunchPolicy,
    ) -> BrokerResult<Option<LifecycleRecord>> {
        let Some(record) = self.records.get(request) else {
            return Ok(None);
        };
        if record.unit != unit || !record.identity.matches_policy(policy) {
            return Err(BrokerError::Conflict(
                "lifecycle request conflicts with its immutable launch identity".to_owned(),
            ));
        }
        Ok(Some(match record.state {
            LedgerState::Pending => LifecycleRecord::Pending,
            LedgerState::Committed => {
                LifecycleRecord::Committed(record.receipt.clone().ok_or_else(|| {
                    BrokerError::Conflict(
                        "broker committed record has no persisted receipt".to_owned(),
                    )
                })?)
            }
            LedgerState::StopPending => {
                LifecycleRecord::StopPending(record.receipt.clone().ok_or_else(|| {
                    BrokerError::Conflict(
                        "broker stop-pending record has no persisted receipt".to_owned(),
                    )
                })?)
            }
            LedgerState::Stopped => {
                LifecycleRecord::Stopped(record.receipt.clone().ok_or_else(|| {
                    BrokerError::Conflict(
                        "broker stopped record has no persisted receipt".to_owned(),
                    )
                })?)
            }
        }))
    }

    #[cfg(test)]
    pub(in crate::platform::linux_broker) fn state(
        &self,
        request: &BrokerRequest,
    ) -> Option<LedgerState> {
        self.records.get(request).map(|record| record.state)
    }

    pub(in crate::platform::linux_broker) fn begin_stop(
        &mut self,
        request: &BrokerRequest,
        receipt: &LaunchReceipt,
    ) -> BrokerResult<()> {
        self.ensure_healthy()?;
        let Some(previous) = self.records.get(request) else {
            return Err(BrokerError::Conflict(
                "broker stop has no durable launch reservation".to_owned(),
            ));
        };
        if previous.state == LedgerState::StopPending {
            let Some(previous_receipt) = previous.receipt.as_ref() else {
                return Err(BrokerError::Conflict(
                    "broker stop-pending record has no persisted receipt".to_owned(),
                ));
            };
            if !same_process_binding(previous_receipt, receipt) {
                return Err(BrokerError::Conflict(
                    "broker stop-pending record has a different process identity".to_owned(),
                ));
            }
            return Ok(());
        }
        if previous.state != LedgerState::Committed {
            return Err(BrokerError::Conflict(
                "broker launch is not committed for stop".to_owned(),
            ));
        }
        let Some(previous_receipt) = previous.receipt.as_ref() else {
            return Err(BrokerError::Conflict(
                "broker committed record has no persisted receipt".to_owned(),
            ));
        };
        if !same_process_binding(previous_receipt, receipt)
            || previous.unit != receipt.unit
            || receipt.request != *request
        {
            return Err(BrokerError::Conflict(
                "broker stop receipt does not match durable reservation".to_owned(),
            ));
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: receipt.unit.clone(),
            identity: previous.identity.clone(),
            bootstrap: previous.bootstrap.clone(),
            job: previous.job.clone(),
            cancel_requested: None,
            state: LedgerState::StopPending,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(in crate::platform::linux_broker) fn begin_failed_launch_cleanup(
        &mut self,
        request: &BrokerRequest,
        receipt: &LaunchReceipt,
        policy: &LaunchPolicy,
    ) -> BrokerResult<()> {
        self.ensure_healthy()?;
        let previous = self.records.get(request).ok_or_else(|| {
            BrokerError::Conflict("failed launch has no durable reservation".to_owned())
        })?;
        if previous.state != LedgerState::Pending {
            return self.begin_stop(request, receipt);
        }
        if !previous.identity.matches_policy(policy) || previous.unit != unit_name(request) {
            return Err(BrokerError::Conflict(
                "failed launch policy differs from reservation".to_owned(),
            ));
        }
        verify_receipt_identity(receipt, request, &previous.unit, policy)?;
        let record = LedgerRecord {
            request: request.clone(),
            unit: previous.unit.clone(),
            identity: previous.identity.clone(),
            bootstrap: previous.bootstrap.clone(),
            job: previous.job.clone(),
            cancel_requested: previous.cancel_requested,
            state: LedgerState::StopPending,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(in crate::platform::linux_broker) fn mark_stopped(
        &mut self,
        request: &BrokerRequest,
        receipt: &LaunchReceipt,
    ) -> BrokerResult<()> {
        self.ensure_healthy()?;
        let Some(previous) = self.records.get(request) else {
            return Err(BrokerError::Conflict(
                "broker stop has no durable launch reservation".to_owned(),
            ));
        };
        let Some(previous_receipt) = previous.receipt.as_ref() else {
            return Err(BrokerError::Conflict(
                "broker stop-pending record has no persisted receipt".to_owned(),
            ));
        };
        if previous.state != LedgerState::StopPending
            || !same_process_binding(previous_receipt, receipt)
        {
            return Err(BrokerError::Conflict(
                "broker stopped receipt does not match the pending stop binding".to_owned(),
            ));
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: receipt.unit.clone(),
            identity: previous.identity.clone(),
            bootstrap: previous.bootstrap.clone(),
            job: previous.job.clone(),
            cancel_requested: previous.cancel_requested,
            state: LedgerState::Stopped,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(in crate::platform::linux_broker) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(in crate::platform::linux_broker) fn ensure_healthy(&self) -> BrokerResult<()> {
        if self.poisoned {
            return Err(BrokerError::Unavailable(
                "broker ledger is poisoned; reopen it from verified durable state".to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn inject_partial_write_failure(&mut self) {
        self.append_failure = Some(AppendFailure::PartialWrite);
    }

    #[cfg(test)]
    pub(crate) fn inject_sync_failure(&mut self) {
        self.append_failure = Some(AppendFailure::Sync);
    }

    #[cfg(test)]
    pub(in crate::platform::linux_broker) fn inject_commit_rejection(&mut self) {
        self.reject_next_commit = true;
    }

    pub(in crate::platform::linux_broker) fn reserve(
        &mut self,
        request: &BrokerRequest,
        unit: &str,
        policy: &LaunchPolicy,
    ) -> BrokerResult<bool> {
        self.reserve_with_bootstrap(request, unit, policy, None)
    }

    pub(in crate::platform::linux_broker) fn reserve_with_bootstrap(
        &mut self,
        request: &BrokerRequest,
        unit: &str,
        policy: &LaunchPolicy,
        bootstrap: Option<&bootstrap::BrokerBootstrapBinding>,
    ) -> BrokerResult<bool> {
        self.ensure_healthy()?;
        if let Some(binding) = bootstrap {
            binding.validate(request)?;
        }
        let identity = LaunchIdentity::from_policy(policy);
        if let Some(record) = self.records.get(request) {
            if record.unit != unit || !record.identity.matches_policy(policy) {
                return Err(BrokerError::Conflict(
                    "broker ledger identity conflicts with current launch policy".to_owned(),
                ));
            }
            if record.bootstrap.as_ref() != bootstrap {
                return Err(BrokerError::Conflict(
                    "broker launch bootstrap conflicts with its durable binding".to_owned(),
                ));
            }
            if matches!(
                record.state,
                LedgerState::StopPending | LedgerState::Stopped
            ) {
                return Err(BrokerError::Conflict(
                    "broker lifecycle stop owns this launch nonce".to_owned(),
                ));
            }
            if record.cancel_requested == Some(true) {
                return Err(BrokerError::Conflict(
                    "broker launch cancellation owns this pending nonce".to_owned(),
                ));
            }
            return Ok(false);
        }
        if self.records.len() >= MAX_LEDGER_REQUESTS {
            return Err(BrokerError::Unavailable(
                "broker idempotence ledger capacity is exhausted".to_owned(),
            ));
        }
        // Pending launches and interrupted stops may still own processes even
        // when this broker incarnation has not observed them. Admission uses
        // durable reservations, not merely the in-memory active-unit cache.
        if self
            .records
            .values()
            .filter(|record| record.state != LedgerState::Stopped)
            .count()
            >= MAX_ACTIVE_PROCESSES
        {
            return Err(BrokerError::Unavailable(
                "broker unresolved-process capacity is exhausted".to_owned(),
            ));
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: unit.to_owned(),
            identity,
            bootstrap: bootstrap.cloned(),
            job: None,
            cancel_requested: None,
            state: LedgerState::Pending,
            receipt: None,
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(true)
    }

    /// Persist the exact object identity returned by `StartTransientUnit`.
    /// This is a second append in the existing pending transition: callers
    /// must invoke it immediately after the manager reply and before any
    /// acknowledgement or retry decision.  A missing binding remains an
    /// unresolved legacy reservation and never authorizes pathname adoption.
    pub(in crate::platform::linux_broker) fn bind_job(
        &mut self,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
        job: &JobBinding,
    ) -> BrokerResult<()> {
        self.ensure_healthy()?;
        job.validate_for_request(request)?;
        let Some(previous) = self.records.get(request) else {
            return Err(BrokerError::Conflict(
                "broker job binding has no durable launch reservation".to_owned(),
            ));
        };
        if previous.unit != job.unit() || !previous.identity.matches_policy(policy) {
            return Err(BrokerError::Conflict(
                "broker job binding conflicts with its launch identity".to_owned(),
            ));
        }
        if let Some(existing) = &previous.job {
            if existing == job {
                return Ok(());
            }
            return Err(BrokerError::Conflict(
                "broker launch has a different durable job binding".to_owned(),
            ));
        }
        if previous.state != LedgerState::Pending {
            return Err(BrokerError::Conflict(
                "broker job binding can only extend a pending launch".to_owned(),
            ));
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: previous.unit.clone(),
            identity: previous.identity.clone(),
            bootstrap: previous.bootstrap.clone(),
            job: Some(job.clone()),
            cancel_requested: previous.cancel_requested,
            state: previous.state,
            receipt: previous.receipt.clone(),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    /// Return the exact retained job binding after checking the request and
    /// fixed policy.  `None` is meaningful: old records without a manager
    /// object identity cannot be upgraded into a pathname-based cleanup path.
    pub(in crate::platform::linux_broker) fn job_binding(
        &self,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
    ) -> BrokerResult<Option<JobBinding>> {
        self.ensure_healthy()?;
        let Some(record) = self.records.get(request) else {
            return Ok(None);
        };
        let unit = unit_name(request);
        if record.unit != unit || !record.identity.matches_policy(policy) {
            return Err(BrokerError::Conflict(
                "broker job lookup conflicts with its launch identity".to_owned(),
            ));
        }
        if let Some(job) = &record.job {
            job.validate_for_request(request)?;
        }
        Ok(record.job.clone())
    }

    /// Persist a Stop intent for a still-pending launch before touching the
    /// manager job.  Repeating the request is idempotent; the bit is never
    /// cleared or interpreted as proof of cancellation.
    pub(in crate::platform::linux_broker) fn request_pending_stop(
        &mut self,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
    ) -> BrokerResult<()> {
        self.ensure_healthy()?;
        let Some(previous) = self.records.get(request) else {
            return Err(BrokerError::Conflict(
                "pending stop has no durable launch reservation".to_owned(),
            ));
        };
        if previous.state != LedgerState::Pending {
            return Err(BrokerError::Conflict(
                "pending stop requires a pending launch reservation".to_owned(),
            ));
        }
        if previous.unit != unit_name(request) || !previous.identity.matches_policy(policy) {
            return Err(BrokerError::Conflict(
                "pending stop conflicts with its immutable launch identity".to_owned(),
            ));
        }
        if previous.cancel_requested == Some(true) {
            return Ok(());
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: previous.unit.clone(),
            identity: previous.identity.clone(),
            bootstrap: previous.bootstrap.clone(),
            job: previous.job.clone(),
            cancel_requested: Some(true),
            state: previous.state,
            receipt: previous.receipt.clone(),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(in crate::platform::linux_broker) fn pending_cancel_requested(
        &self,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
    ) -> BrokerResult<bool> {
        self.ensure_healthy()?;
        let Some(record) = self.records.get(request) else {
            return Ok(false);
        };
        if record.state != LedgerState::Pending {
            return Ok(false);
        }
        if record.unit != unit_name(request) || !record.identity.matches_policy(policy) {
            return Err(BrokerError::Conflict(
                "pending cancellation conflicts with its immutable launch identity".to_owned(),
            ));
        }
        Ok(record.cancel_requested == Some(true))
    }

    /// Return a queued-job binding only for a still-pending reservation.  A
    /// committed or terminal record is handled by its receipt/containment
    /// identity, not by attempting to reuse an old manager job object.
    pub(in crate::platform::linux_broker) fn pending_job_binding(
        &self,
        request: &BrokerRequest,
        policy: &LaunchPolicy,
    ) -> BrokerResult<Option<JobBinding>> {
        let Some(record) = self.records.get(request) else {
            return Ok(None);
        };
        if record.state != LedgerState::Pending {
            return Ok(None);
        }
        self.job_binding(request, policy)
    }

    pub(in crate::platform::linux_broker) fn commit(
        &mut self,
        request: &BrokerRequest,
        receipt: &LaunchReceipt,
    ) -> BrokerResult<()> {
        self.ensure_healthy()?;
        #[cfg(test)]
        if std::mem::take(&mut self.reject_next_commit) {
            return Err(BrokerError::Unavailable(
                "injected pre-write commit rejection".to_owned(),
            ));
        }
        let Some(previous) = self.records.get(request) else {
            return Err(BrokerError::Conflict(
                "broker launch has no durable reservation".to_owned(),
            ));
        };
        if matches!(
            previous.state,
            LedgerState::StopPending | LedgerState::Stopped
        ) {
            return Err(BrokerError::Conflict(
                "broker lifecycle stop owns this launch nonce".to_owned(),
            ));
        }
        if previous.unit != receipt.unit || receipt.request != *request {
            return Err(BrokerError::Conflict(
                "broker receipt does not match durable reservation".to_owned(),
            ));
        }
        if previous.state == LedgerState::Committed {
            let Some(previous_receipt) = previous.receipt.as_ref() else {
                return Err(BrokerError::Conflict(
                    "broker committed record has no persisted receipt".to_owned(),
                ));
            };
            if !same_process_binding(previous_receipt, receipt) {
                return Err(BrokerError::Conflict(
                    "broker duplicate receipt has a different process identity".to_owned(),
                ));
            }
            return Ok(());
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: receipt.unit.clone(),
            identity: previous.identity.clone(),
            bootstrap: previous.bootstrap.clone(),
            job: previous.job.clone(),
            cancel_requested: previous.cancel_requested,
            state: LedgerState::Committed,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(super) fn append(&mut self, record: &LedgerRecord) -> BrokerResult<()> {
        let bytes =
            serde_json::to_vec(record).map_err(|error| BrokerError::Io(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "broker ledger record exceeds size bound".to_owned(),
            ));
        }
        let Some(path) = self.path.clone() else {
            return Ok(());
        };
        let parent = path
            .parent()
            .ok_or_else(|| BrokerError::Invalid("broker ledger has no parent".to_owned()))?;
        validate_protected_directory(parent, "broker ledger directory")?;
        let mut options = fs::OpenOptions::new();
        options.append(true).write(true).mode(0o600);
        let mut file = options.open(path).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || !is_protected_owner(metadata.uid())
            || metadata.mode() & 0o077 != 0
        {
            return Err(BrokerError::Unauthorized(
                "broker ledger ownership or mode is unsafe".to_owned(),
            ));
        }
        if metadata.len().saturating_add(bytes.len() as u64 + 1) > MAX_LEDGER_BYTES as u64 {
            return Err(BrokerError::Unavailable(
                "broker ledger aggregate size exceeds its reopen bound".to_owned(),
            ));
        }

        #[cfg(test)]
        let append_failure = self.append_failure.take();

        #[cfg(test)]
        if append_failure == Some(AppendFailure::PartialWrite) {
            let partial_len = (bytes.len() / 2).max(1);
            if let Err(error) = file.write_all(&bytes[..partial_len]) {
                self.poisoned = true;
                return Err(io_error(error));
            }
            self.poisoned = true;
            return Err(BrokerError::Io(
                "injected partial broker ledger append failure".to_owned(),
            ));
        }

        if let Err(error) = file.write_all(&bytes) {
            self.poisoned = true;
            return Err(io_error(error));
        }
        if let Err(error) = file.write_all(b"\n") {
            self.poisoned = true;
            return Err(io_error(error));
        }

        #[cfg(test)]
        if append_failure == Some(AppendFailure::Sync) {
            self.poisoned = true;
            return Err(BrokerError::Io(
                "injected broker ledger sync failure".to_owned(),
            ));
        }

        if let Err(error) = file.sync_all() {
            self.poisoned = true;
            return Err(io_error(error));
        }
        Ok(())
    }
}

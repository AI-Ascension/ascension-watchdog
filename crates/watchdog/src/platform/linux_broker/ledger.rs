#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum LedgerState {
    Pending,
    Committed,
    StopPending,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerRecord {
    request: BrokerRequest,
    unit: String,
    identity: LaunchIdentity,
    // Legacy records omit this field. A typed launch records only the
    // immutable, non-secret binding; stdin bytes are never journaled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bootstrap: Option<bootstrap::BrokerBootstrapBinding>,
    state: LedgerState,
    receipt: Option<LaunchReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum LifecycleRecord {
    Pending,
    Committed(LaunchReceipt),
    StopPending(LaunchReceipt),
    Stopped(LaunchReceipt),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LaunchIdentity {
    executable: PathBuf,
    executable_sha256: String,
    arguments: Vec<String>,
    working_directory: PathBuf,
    environment: Vec<(String, String)>,
    target_uid: u32,
    target_gid: u32,
    capability_bounding_set: u64,
    ambient_capabilities: u64,
    no_new_privileges: bool,
    tasks_max: u64,
    memory_max_bytes: u64,
    timeout_nanos: u64,
}

impl LaunchIdentity {
    fn from_policy(policy: &LaunchPolicy) -> Self {
        Self {
            executable: policy.executable.clone(),
            executable_sha256: policy.executable_sha256.clone(),
            arguments: policy.arguments.clone(),
            working_directory: policy.working_directory.clone(),
            environment: policy.environment.clone(),
            target_uid: policy.target_uid,
            target_gid: policy.target_gid,
            capability_bounding_set: policy.capabilities.bounding_set,
            ambient_capabilities: policy.capabilities.ambient_set,
            no_new_privileges: policy.capabilities.no_new_privileges,
            tasks_max: policy.cgroup.tasks_max,
            memory_max_bytes: policy.cgroup.memory_max_bytes,
            timeout_nanos: policy.timeout.as_nanos().try_into().unwrap_or(u64::MAX),
        }
    }

    pub(super) fn matches_policy(&self, policy: &LaunchPolicy) -> bool {
        self == &Self::from_policy(policy)
    }
}

/// Durable idempotence journal. A pending record is written and synced before
/// StartTransientUnit. If the broker dies after the effect, a later broker can
/// inspect the exact unit; an inactive or missing unit is never relaunched from
/// an old nonce.
#[derive(Debug)]
pub struct BrokerLedger {
    path: Option<PathBuf>,
    records: BTreeMap<BrokerRequest, LedgerRecord>,
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
    pub(super) fn recoverable_receipts(
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

    pub(super) fn contains(&self, request: &BrokerRequest) -> bool {
        self.records.contains_key(request)
    }

    pub(super) fn lifecycle_record(
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
    pub(super) fn state(&self, request: &BrokerRequest) -> Option<LedgerState> {
        self.records.get(request).map(|record| record.state)
    }

    pub(super) fn begin_stop(
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
            state: LedgerState::StopPending,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(super) fn begin_failed_launch_cleanup(
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
            state: LedgerState::StopPending,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(super) fn mark_stopped(
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
            state: LedgerState::Stopped,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    pub(super) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(super) fn ensure_healthy(&self) -> BrokerResult<()> {
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
    pub(super) fn inject_commit_rejection(&mut self) {
        self.reject_next_commit = true;
    }

    pub(super) fn reserve(
        &mut self,
        request: &BrokerRequest,
        unit: &str,
        policy: &LaunchPolicy,
    ) -> BrokerResult<bool> {
        self.reserve_with_bootstrap(request, unit, policy, None)
    }

    pub(super) fn reserve_with_bootstrap(
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
            state: LedgerState::Pending,
            receipt: None,
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(true)
    }

    pub(super) fn commit(
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
            state: LedgerState::Committed,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    fn append(&mut self, record: &LedgerRecord) -> BrokerResult<()> {
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

// The serialized launch policy additionally persists no_new_privileges=true;
// all admitted policies require it, and live observations check it before
// any effect. It is therefore invariant, not a variable receipt field. Native
// retained-capability equality also compares the full UnitObservation.
pub(super) fn same_process_binding(previous: &LaunchReceipt, current: &LaunchReceipt) -> bool {
    previous.request == current.request
        && previous.unit == current.unit
        && previous.pid == current.pid
        && previous.creation_token == current.creation_token
        && previous.executable == current.executable
        && previous.executable_sha256 == current.executable_sha256
        && previous.uid == current.uid
        && previous.gid == current.gid
        && previous.capability_bounding_set == current.capability_bounding_set
        && previous.ambient_capabilities == current.ambient_capabilities
        && previous.control_group == current.control_group
}

fn parse_records(bytes: &[u8]) -> BrokerResult<BTreeMap<BrokerRequest, LedgerRecord>> {
    let mut records = BTreeMap::<BrokerRequest, LedgerRecord>::new();
    let mut transition_count = 0;
    let mut units = BTreeMap::<String, BrokerRequest>::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        transition_count += 1;
        if transition_count > MAX_LEDGER_TRANSITIONS {
            return Err(BrokerError::Invalid(
                "broker ledger transition count exceeds bound".to_owned(),
            ));
        }
        let record: LedgerRecord = parse_json(line, "broker ledger record")?;
        record.request.validate()?;
        if let Some(binding) = &record.bootstrap {
            binding.validate(&record.request)?;
        }
        if record.unit != unit_name(&record.request) {
            return Err(BrokerError::Conflict(
                "broker ledger unit does not match request identity".to_owned(),
            ));
        }
        if let Some(previous_request) = units.get(&record.unit)
            && previous_request != &record.request
        {
            return Err(BrokerError::Conflict(
                "broker ledger unit is claimed by multiple requests".to_owned(),
            ));
        }
        units.insert(record.unit.clone(), record.request.clone());
        if !records.contains_key(&record.request) && records.len() >= MAX_LEDGER_REQUESTS {
            return Err(BrokerError::Invalid(
                "broker ledger distinct request count exceeds bound".to_owned(),
            ));
        }
        match (records.get(&record.request), record.state, &record.receipt) {
            (None, LedgerState::Pending, None) => {}
            (None, LedgerState::Committed, _) => {
                return Err(BrokerError::Invalid(
                    "broker ledger committed record lacks a pending predecessor".to_owned(),
                ));
            }
            (None, LedgerState::StopPending | LedgerState::Stopped, _) => {
                return Err(BrokerError::Invalid(
                    "broker ledger lifecycle record lacks a committed predecessor".to_owned(),
                ));
            }
            (None, LedgerState::Pending, Some(_)) => {
                return Err(BrokerError::Invalid(
                    "pending broker ledger record must not have a receipt".to_owned(),
                ));
            }
            (Some(_previous), LedgerState::Pending, _) => {
                return Err(BrokerError::Invalid(
                    "broker ledger has a duplicate or regressed pending record".to_owned(),
                ));
            }
            (
                Some(previous),
                state @ (LedgerState::Committed | LedgerState::StopPending | LedgerState::Stopped),
                Some(receipt),
            ) => {
                let expected_previous = match state {
                    LedgerState::Committed => LedgerState::Pending,
                    LedgerState::StopPending => LedgerState::Committed,
                    LedgerState::Stopped => LedgerState::StopPending,
                    LedgerState::Pending => {
                        return Err(BrokerError::Invalid(
                            "broker ledger pending transition is invalid".to_owned(),
                        ));
                    }
                };
                let failed_launch_cleanup = state == LedgerState::StopPending
                    && previous.state == LedgerState::Pending
                    && previous.receipt.is_none();
                if (!failed_launch_cleanup && previous.state != expected_previous)
                    || previous.unit != record.unit
                    || previous.identity != record.identity
                    || previous.bootstrap != record.bootstrap
                    || previous
                        .receipt
                        .as_ref()
                        .is_some_and(|prior| !same_process_binding(prior, receipt))
                    || receipt.request != record.request
                    || receipt.unit != record.unit
                    || receipt.executable != record.identity.executable
                    || receipt.executable_sha256 != record.identity.executable_sha256
                    || receipt.pid == 0
                    || receipt.creation_token.is_empty()
                    || receipt.uid != record.identity.target_uid
                    || receipt.gid != record.identity.target_gid
                    || receipt.capability_bounding_set != record.identity.capability_bounding_set
                    || receipt.ambient_capabilities != record.identity.ambient_capabilities
                    || !receipt
                        .control_group
                        .ends_with(&format!("/{}", record.unit))
                {
                    return Err(BrokerError::Conflict(
                        "broker ledger committed record is inconsistent".to_owned(),
                    ));
                }
            }
            (
                Some(_),
                LedgerState::Committed | LedgerState::StopPending | LedgerState::Stopped,
                None,
            ) => {
                return Err(BrokerError::Invalid(
                    "terminal broker ledger record lacks a receipt".to_owned(),
                ));
            }
        }
        records.insert(record.request.clone(), record);
    }
    Ok(records)
}

fn sync_directory(path: &Path) -> BrokerResult<()> {
    File::open(path)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}

fn validate_protected_ledger_path(path: &Path) -> BrokerResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| BrokerError::Invalid("broker ledger has no parent".to_owned()))?;
    validate_protected_directory(parent, "broker ledger directory")?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(BrokerError::Invalid(
            "broker ledger must not be a symlink".to_owned(),
        )),
        Ok(metadata) if !metadata.is_file() => Err(BrokerError::Invalid(
            "broker ledger must be a regular file".to_owned(),
        )),
        Ok(metadata) if !is_protected_owner(metadata.uid()) || metadata.mode() & 0o077 != 0 => Err(
            BrokerError::Invalid("broker ledger must be root-owned and mode 0600".to_owned()),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(nonce: &str) -> BrokerRequest {
        BrokerRequest {
            component: BrokerComponent::Synthetic,
            instance: "instance".to_owned(),
            incarnation: "incarnation".to_owned(),
            nonce: nonce.to_owned(),
        }
    }

    fn identity() -> LaunchIdentity {
        LaunchIdentity {
            executable: PathBuf::from("/usr/bin/true"),
            executable_sha256: "0".repeat(64),
            arguments: Vec::new(),
            working_directory: PathBuf::from("/"),
            environment: Vec::new(),
            target_uid: 1001,
            target_gid: 1001,
            capability_bounding_set: 0,
            ambient_capabilities: 0,
            no_new_privileges: true,
            tasks_max: 16,
            memory_max_bytes: 64 * 1024 * 1024,
            timeout_nanos: 2_000_000_000,
        }
    }

    fn pending(nonce: &str) -> LedgerRecord {
        let request = request(nonce);
        LedgerRecord {
            unit: unit_name(&request),
            request,
            identity: identity(),
            bootstrap: None,
            state: LedgerState::Pending,
            receipt: None,
        }
    }

    fn encode(records: &[LedgerRecord]) -> Vec<u8> {
        records
            .iter()
            .flat_map(|record| {
                let mut bytes = serde_json::to_vec(record).expect("test record JSON");
                bytes.push(b'\n');
                bytes
            })
            .collect()
    }

    fn lifecycle(nonce: &str, argument_bytes: usize) -> Vec<LedgerRecord> {
        let mut record = pending(nonce);
        record.identity.arguments = vec!["x".repeat(argument_bytes)];
        let mut records = vec![record.clone()];
        record.receipt = Some(LaunchReceipt {
            request: record.request.clone(),
            unit: record.unit.clone(),
            pid: 42,
            creation_token: "1234".to_owned(),
            executable: record.identity.executable.clone(),
            executable_sha256: record.identity.executable_sha256.clone(),
            uid: record.identity.target_uid,
            gid: record.identity.target_gid,
            capability_bounding_set: 0,
            ambient_capabilities: 0,
            control_group: format!("/system.slice/{}", record.unit),
            duplicate: false,
        });
        for state in [
            LedgerState::Committed,
            LedgerState::StopPending,
            LedgerState::Stopped,
        ] {
            record.state = state;
            records.push(record.clone());
        }
        records
    }

    #[test]
    fn full_capacity_large_lifecycles_remain_reopenable() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempfile::tempdir_in(std::env::current_dir()?)?;
        let path = directory.path().join("ledger.jsonl");
        let mut ledger = BrokerLedger::init(&path)?;
        for index in 0..MAX_LEDGER_REQUESTS {
            for record in lifecycle(&format!("nonce-{index}"), 7_000) {
                ledger.append(&record)?;
            }
        }
        assert!(fs::metadata(&path)?.len() > 1024 * 1024);
        drop(ledger);
        let reopened = BrokerLedger::open(path)?;
        assert_eq!(reopened.records.len(), MAX_LEDGER_REQUESTS);
        assert!(
            reopened
                .records
                .values()
                .all(|record| record.state == LedgerState::Stopped)
        );
        Ok(())
    }

    #[test]
    fn lifecycle_parser_rejects_changed_process_binding() {
        for changed_state in [2, 3] {
            for change_birth in [false, true] {
                let mut records = lifecycle("changed-process", 0);
                let receipt = records[changed_state]
                    .receipt
                    .as_mut()
                    .expect("lifecycle receipt");
                if change_birth {
                    receipt.creation_token = "5678".to_owned();
                } else {
                    receipt.pid += 1;
                }
                assert!(parse_records(&encode(&records)).is_err());
            }
        }
    }

    #[test]
    fn append_cannot_exceed_the_reopen_byte_bound() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir_in(std::env::current_dir()?)?;
        let path = directory.path().join("ledger.jsonl");
        let mut ledger = BrokerLedger::init(&path)?;
        let file = fs::OpenOptions::new().write(true).open(&path)?;
        file.set_len(MAX_LEDGER_BYTES as u64)?;
        assert!(ledger.append(&pending("over-limit")).is_err());
        assert_eq!(fs::metadata(&path)?.len(), MAX_LEDGER_BYTES as u64);
        Ok(())
    }

    #[test]
    fn parser_rejects_duplicate_pending_records() {
        let record = pending("duplicate");
        assert!(parse_records(&encode(&[record.clone(), record])).is_err());
    }

    #[test]
    fn parser_rejects_committed_records_without_pending_history() {
        let mut record = pending("committed-first");
        record.state = LedgerState::Committed;
        assert!(parse_records(&encode(&[record])).is_err());
    }

    fn typed_binding() -> bootstrap::BrokerBootstrapBinding {
        bootstrap::BrokerBootstrapBinding {
            version: 2,
            kind: bootstrap::BootstrapKind::GatewayHealth,
            watchdog_boot_id: "00000000-0000-4000-8000-000000000022".to_owned(),
            frame_sha256: "a".repeat(64),
        }
    }

    fn typed_lifecycle() -> Vec<LedgerRecord> {
        let mut records = lifecycle("00000000-0000-4000-8000-000000000011", 0);
        for record in &mut records {
            record.request.component = BrokerComponent::Gateway;
            record.unit = unit_name(&record.request);
            record.bootstrap = Some(typed_binding());
            if let Some(receipt) = &mut record.receipt {
                receipt.request = record.request.clone();
                receipt.unit = record.unit.clone();
                receipt.control_group = format!("/system.slice/{}", record.unit);
            }
        }
        records
    }

    fn launch_policy() -> LaunchPolicy {
        let identity = identity();
        LaunchPolicy {
            executable: identity.executable,
            executable_sha256: identity.executable_sha256,
            arguments: identity.arguments,
            working_directory: identity.working_directory,
            environment: identity.environment,
            target_uid: identity.target_uid,
            target_gid: identity.target_gid,
            capabilities: CapabilityPolicy {
                bounding_set: identity.capability_bounding_set,
                ambient_set: identity.ambient_capabilities,
                no_new_privileges: identity.no_new_privileges,
            },
            cgroup: CgroupPolicy {
                tasks_max: identity.tasks_max,
                memory_max_bytes: identity.memory_max_bytes,
            },
            timeout: Duration::from_nanos(identity.timeout_nanos),
        }
    }

    #[test]
    fn typed_reservation_rejects_changed_frame_boot_and_legacy_downgrade()
    -> Result<(), Box<dyn std::error::Error>> {
        let records = typed_lifecycle();
        let first = &records[0];
        let policy = launch_policy();
        let binding = typed_binding();
        let mut ledger = BrokerLedger::memory();
        assert!(ledger.reserve_with_bootstrap(
            &first.request,
            &first.unit,
            &policy,
            Some(&binding)
        )?);
        assert!(!ledger.reserve_with_bootstrap(
            &first.request,
            &first.unit,
            &policy,
            Some(&binding)
        )?);
        assert!(
            ledger
                .reserve(&first.request, &first.unit, &policy)
                .is_err()
        );
        let mut changed = binding.clone();
        changed.frame_sha256 = "b".repeat(64);
        assert!(
            ledger
                .reserve_with_bootstrap(&first.request, &first.unit, &policy, Some(&changed))
                .is_err()
        );
        changed = binding;
        changed.watchdog_boot_id = "00000000-0000-4000-8000-000000000033".to_owned();
        assert!(
            ledger
                .reserve_with_bootstrap(&first.request, &first.unit, &policy, Some(&changed))
                .is_err()
        );
        assert_eq!(ledger.state(&first.request), Some(LedgerState::Pending));
        assert_eq!(ledger.records.len(), 1);
        Ok(())
    }

    #[test]
    fn legacy_reservation_cannot_be_upgraded_to_typed_stdin()
    -> Result<(), Box<dyn std::error::Error>> {
        let records = typed_lifecycle();
        let first = &records[0];
        let policy = launch_policy();
        let mut ledger = BrokerLedger::memory();
        assert!(ledger.reserve(&first.request, &first.unit, &policy)?);
        assert!(
            ledger
                .reserve_with_bootstrap(
                    &first.request,
                    &first.unit,
                    &policy,
                    Some(&typed_binding())
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn typed_lifecycle_binding_is_immutable_on_reopen() {
        let original = typed_lifecycle();
        assert!(parse_records(&encode(&original)).is_ok());
        for index in 1..original.len() {
            for remove in [false, true] {
                let mut records = original.clone();
                if remove {
                    records[index].bootstrap = None;
                } else {
                    records[index]
                        .bootstrap
                        .as_mut()
                        .expect("typed binding")
                        .frame_sha256 = "b".repeat(64);
                }
                assert!(parse_records(&encode(&records)).is_err());
            }
        }
    }

    #[test]
    fn typed_ledger_reopens_binding_and_legacy_encoding_stays_unchanged()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir_in(std::env::current_dir()?)?;
        let path = directory.path().join("typed-ledger.jsonl");
        let mut ledger = BrokerLedger::init(&path)?;
        for record in typed_lifecycle() {
            ledger.append(&record)?;
        }
        drop(ledger);
        let reopened = BrokerLedger::open(path)?;
        let record = reopened.records.values().next().expect("one typed record");
        assert_eq!(record.bootstrap, Some(typed_binding()));
        assert_eq!(record.state, LedgerState::Stopped);
        let legacy = encode(&lifecycle("legacy", 0));
        assert!(!String::from_utf8(legacy.clone())?.contains("bootstrap"));
        assert!(parse_records(&legacy).is_ok());
        Ok(())
    }
}

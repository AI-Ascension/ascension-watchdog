#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum LedgerState {
    Pending,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct LedgerRecord {
    request: BrokerRequest,
    unit: String,
    identity: LaunchIdentity,
    state: LedgerState,
    receipt: Option<LaunchReceipt>,
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

    fn matches_policy(&self, policy: &LaunchPolicy) -> bool {
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
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AppendFailure {
    PartialWrite,
    Sync,
}

impl BrokerLedger {
    pub fn memory() -> Self {
        Self {
            path: None,
            records: BTreeMap::new(),
            poisoned: false,
            #[cfg(test)]
            append_failure: None,
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

    pub(super) fn reserve(
        &mut self,
        request: &BrokerRequest,
        unit: &str,
        policy: &LaunchPolicy,
    ) -> BrokerResult<bool> {
        self.ensure_healthy()?;
        let identity = LaunchIdentity::from_policy(policy);
        if let Some(record) = self.records.get(request) {
            if record.unit != unit || !record.identity.matches_policy(policy) {
                return Err(BrokerError::Conflict(
                    "broker ledger identity conflicts with current launch policy".to_owned(),
                ));
            }
            return Ok(false);
        }
        if self.records.len() >= MAX_LEDGER_RECORDS {
            return Err(BrokerError::Unavailable(
                "broker idempotence ledger capacity is exhausted".to_owned(),
            ));
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: unit.to_owned(),
            identity,
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
        let Some(previous) = self.records.get(request) else {
            return Err(BrokerError::Conflict(
                "broker launch has no durable reservation".to_owned(),
            ));
        };
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
            state: LedgerState::Committed,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    fn append(&mut self, record: &LedgerRecord) -> BrokerResult<()> {
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
        let bytes =
            serde_json::to_vec(record).map_err(|error| BrokerError::Io(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "broker ledger record exceeds size bound".to_owned(),
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

fn same_process_binding(previous: &LaunchReceipt, current: &LaunchReceipt) -> bool {
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
    let mut record_count = 0;
    let mut units = BTreeMap::<String, BrokerRequest>::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        record_count += 1;
        if record_count > MAX_LEDGER_RECORDS {
            return Err(BrokerError::Invalid(
                "broker ledger record count exceeds bound".to_owned(),
            ));
        }
        let record: LedgerRecord = parse_json(line, "broker ledger record")?;
        record.request.validate()?;
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
        match (records.get(&record.request), record.state, &record.receipt) {
            (None, LedgerState::Pending, None) => {}
            (None, LedgerState::Committed, _) => {
                return Err(BrokerError::Invalid(
                    "broker ledger committed record lacks a pending predecessor".to_owned(),
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
            (Some(previous), LedgerState::Committed, Some(receipt)) => {
                if previous.state != LedgerState::Pending
                    || previous.unit != record.unit
                    || previous.identity != record.identity
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
            (Some(_), LedgerState::Committed, None) => {
                return Err(BrokerError::Invalid(
                    "committed broker ledger record lacks a receipt".to_owned(),
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
}

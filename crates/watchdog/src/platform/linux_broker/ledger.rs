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
    state: LedgerState,
    receipt: Option<LaunchReceipt>,
}

/// Durable idempotence journal. A pending record is written and synced before
/// StartTransientUnit. If the broker dies after the effect, a later broker can
/// inspect the exact unit; an inactive or missing unit is never relaunched from
/// an old nonce.
#[derive(Debug)]
pub struct BrokerLedger {
    path: Option<PathBuf>,
    records: BTreeMap<BrokerRequest, LedgerRecord>,
}

impl BrokerLedger {
    pub fn memory() -> Self {
        Self {
            path: None,
            records: BTreeMap::new(),
        }
    }

    pub fn open(path: impl Into<PathBuf>) -> BrokerResult<Self> {
        let path = path.into();
        validate_protected_ledger_path(&path)?;
        let mut ledger = Self {
            path: Some(path.clone()),
            records: BTreeMap::new(),
        };
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(io_error(error)),
        };
        if let Some(metadata) = metadata {
            if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(BrokerError::Invalid(
                    "broker ledger must be a root-owned mode-0600 regular file".to_owned(),
                ));
            }
            let bytes = read_bounded_file(&path, MAX_LEDGER_BYTES, "broker ledger")?;
            let mut record_count = 0;
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
                if record.unit != unit_name(&record.request) {
                    return Err(BrokerError::Conflict(
                        "broker ledger unit does not match request identity".to_owned(),
                    ));
                }
                if record.state == LedgerState::Committed && record.receipt.is_none() {
                    return Err(BrokerError::Invalid(
                        "committed broker ledger record lacks a receipt".to_owned(),
                    ));
                }
                ledger.records.insert(record.request.clone(), record);
            }
        }
        Ok(ledger)
    }

    pub(super) fn contains(&self, request: &BrokerRequest) -> bool {
        self.records.contains_key(request)
    }

    pub(super) fn reserve(&mut self, request: &BrokerRequest, unit: &str) -> BrokerResult<bool> {
        if let Some(record) = self.records.get(request) {
            if record.unit != unit {
                return Err(BrokerError::Conflict(
                    "broker ledger identity conflicts with generated unit".to_owned(),
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
            return Ok(());
        }
        let record = LedgerRecord {
            request: request.clone(),
            unit: receipt.unit.clone(),
            state: LedgerState::Committed,
            receipt: Some(receipt.clone()),
        };
        self.append(&record)?;
        self.records.insert(request.clone(), record);
        Ok(())
    }

    fn append(&self, record: &LedgerRecord) -> BrokerResult<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path
            .parent()
            .ok_or_else(|| BrokerError::Invalid("broker ledger has no parent".to_owned()))?;
        validate_protected_directory(parent, "broker ledger directory")?;
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true).write(true).mode(0o600);
        let mut file = options.open(path).map_err(io_error)?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
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
        file.write_all(&bytes).map_err(io_error)?;
        file.write_all(b"\n").map_err(io_error)?;
        file.sync_all().map_err(io_error)
    }
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
        Ok(metadata) if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 => Err(
            BrokerError::Invalid("broker ledger must be root-owned and mode 0600".to_owned()),
        ),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

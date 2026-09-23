//! Durable ledger records, decoding and path protection.
//!
//! Extracted verbatim from `ledger.rs`: the persisted record value types, the
//! strict line decoder, the directory/ledger path guards and the immutable
//! process-binding comparison keep their exact encodings and ordering rules.

#[allow(clippy::wildcard_imports)]
use super::super::*;

use super::ledger_binding::JobBinding;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub(in crate::platform::linux_broker) enum LedgerState {
    Pending,
    Committed,
    StopPending,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LedgerRecord {
    pub(super) request: BrokerRequest,
    pub(super) unit: String,
    pub(super) identity: LaunchIdentity,
    // Legacy records omit this field. A typed launch records only the
    // immutable, non-secret binding; stdin bytes are never journaled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) bootstrap: Option<bootstrap::BrokerBootstrapBinding>,
    // Legacy records omit this field. A typed launch retains only the
    // immutable, non-secret object identity returned by StartTransientUnit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) job: Option<JobBinding>,
    // A pending Stop is an intent, not proof that PID 1 did or did not run
    // the transient unit.  Older journals omit this field and therefore
    // decode as an unrequested cancellation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cancel_requested: Option<bool>,
    pub(super) state: LedgerState,
    pub(super) receipt: Option<LaunchReceipt>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::platform::linux_broker) enum LifecycleRecord {
    Pending,
    Committed(LaunchReceipt),
    StopPending(LaunchReceipt),
    Stopped(LaunchReceipt),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchIdentity {
    pub(super) executable: PathBuf,
    pub(super) executable_sha256: String,
    pub(super) arguments: Vec<String>,
    pub(super) working_directory: PathBuf,
    pub(super) environment: Vec<(String, String)>,
    pub(super) target_uid: u32,
    pub(super) target_gid: u32,
    pub(super) capability_bounding_set: u64,
    pub(super) ambient_capabilities: u64,
    pub(super) no_new_privileges: bool,
    pub(super) tasks_max: u64,
    pub(super) memory_max_bytes: u64,
    pub(super) timeout_nanos: u64,
}

impl LaunchIdentity {
    pub(super) fn from_policy(policy: &LaunchPolicy) -> Self {
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

// The serialized launch policy additionally persists no_new_privileges=true;
// all admitted policies require it, and live observations check it before
// any effect. It is therefore invariant, not a variable receipt field. Native
// retained-capability equality also compares the full UnitObservation.
pub(in crate::platform::linux_broker) fn same_process_binding(
    previous: &LaunchReceipt,
    current: &LaunchReceipt,
) -> bool {
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

pub(super) fn parse_records(bytes: &[u8]) -> BrokerResult<BTreeMap<BrokerRequest, LedgerRecord>> {
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
        if let Some(job) = &record.job {
            job.validate_for_request(&record.request)?;
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
            (None, LedgerState::Pending, None) => {
                if record.cancel_requested.is_some() {
                    return Err(BrokerError::Invalid(
                        "broker cancellation intent lacks a pending predecessor".to_owned(),
                    ));
                }
            }
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
            (Some(previous), LedgerState::Pending, None) => {
                // Binding the exact object returned by StartTransientUnit is
                // itself a durable extension of the reservation.  It must be
                // the one and only additional pending record: no receipt is
                // available yet, the predecessor is still unbound, and the
                // new record must carry a binding.  Every other pending
                // append is a duplicate, a regression, or an attempted
                // replacement of immutable launch state.
                let job_binding_extension = previous.state == LedgerState::Pending
                    && previous.receipt.is_none()
                    && previous.job.is_none()
                    && record.job.is_some()
                    && previous.cancel_requested == record.cancel_requested;
                let cancel_intent_extension = previous.state == LedgerState::Pending
                    && previous.receipt.is_none()
                    && previous.cancel_requested.is_none()
                    && record.cancel_requested == Some(true)
                    && previous.job == record.job;
                if (!job_binding_extension && !cancel_intent_extension)
                    || previous.unit != record.unit
                    || previous.identity != record.identity
                    || previous.bootstrap != record.bootstrap
                {
                    return Err(BrokerError::Invalid(
                        "broker ledger has a duplicate or regressed pending record".to_owned(),
                    ));
                }
            }
            (Some(_previous), LedgerState::Pending, Some(_)) => {
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
                    || previous.job != record.job
                    || previous.cancel_requested != record.cancel_requested
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

pub(super) fn sync_directory(path: &Path) -> BrokerResult<()> {
    File::open(path)
        .map_err(io_error)?
        .sync_all()
        .map_err(io_error)
}

pub(super) fn validate_protected_ledger_path(path: &Path) -> BrokerResult<()> {
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

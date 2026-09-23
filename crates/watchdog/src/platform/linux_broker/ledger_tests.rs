//! Ledger unit tests for the durable idempotence journal.

#[allow(clippy::wildcard_imports)]
use super::super::*;

use super::ledger_binding::{JobBinding, SYSTEMD_JOB_PATH_PREFIX};
use super::ledger_records::{LaunchIdentity, LedgerRecord, LedgerState, parse_records};
use super::ledger_store::BrokerLedger;

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
        job: None,
        cancel_requested: None,
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
fn full_capacity_large_lifecycles_remain_reopenable() -> Result<(), Box<dyn std::error::Error>> {
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

#[test]
fn pending_cancel_intent_is_durable_and_cannot_be_cleared() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir_in(std::env::current_dir()?)?;
    let path = directory.path().join("ledger.jsonl");
    let request = request("pending-cancel-intent");
    let unit = unit_name(&request);
    let policy = job_policy();
    let mut ledger = BrokerLedger::init(&path)?;
    assert!(ledger.reserve(&request, &unit, &policy)?);
    let binding = JobBinding::from_object_path(&unit, "/org/freedesktop/systemd1/job/37")?;
    ledger.bind_job(&request, &policy, &binding)?;
    assert!(!ledger.pending_cancel_requested(&request, &policy)?);
    ledger.request_pending_stop(&request, &policy)?;
    ledger.request_pending_stop(&request, &policy)?;
    assert!(ledger.pending_cancel_requested(&request, &policy)?);
    drop(ledger);

    let mut reopened = BrokerLedger::open(path)?;
    assert!(reopened.pending_cancel_requested(&request, &policy)?);
    assert_eq!(
        reopened.pending_job_binding(&request, &policy)?,
        Some(binding)
    );
    assert!(reopened.reserve(&request, &unit, &policy).is_err());
    Ok(())
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

fn job_policy() -> LaunchPolicy {
    launch_policy()
}

#[test]
fn typed_reservation_rejects_changed_frame_boot_and_legacy_downgrade()
-> Result<(), Box<dyn std::error::Error>> {
    let records = typed_lifecycle();
    let first = &records[0];
    let policy = launch_policy();
    let binding = typed_binding();
    let mut ledger = BrokerLedger::memory();
    assert!(ledger.reserve_with_bootstrap(&first.request, &first.unit, &policy, Some(&binding))?);
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
fn legacy_reservation_cannot_be_upgraded_to_typed_stdin() -> Result<(), Box<dyn std::error::Error>>
{
    let records = typed_lifecycle();
    let first = &records[0];
    let policy = launch_policy();
    let mut ledger = BrokerLedger::memory();
    assert!(ledger.reserve(&first.request, &first.unit, &policy)?);
    assert!(
        ledger
            .reserve_with_bootstrap(&first.request, &first.unit, &policy, Some(&typed_binding()))
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
fn job(unit: &str, id: u32) -> JobBinding {
    JobBinding::from_object_path(unit, &format!("{SYSTEMD_JOB_PATH_PREFIX}{id}"))
        .expect("valid systemd job binding")
}

#[test]
fn job_binding_requires_the_canonical_pid1_object_identity() {
    let request = request("job-syntax");
    let unit = unit_name(&request);
    let valid = job(&unit, 17);
    assert_eq!(valid.job_id(), 17);
    assert_eq!(valid.job_path(), format!("{SYSTEMD_JOB_PATH_PREFIX}17"));
    assert!(JobBinding::from_object_path(&unit, "/org/freedesktop/systemd1/job/017").is_err());
    assert!(JobBinding::from_object_path(&unit, "/org/freedesktop/systemd1/job/0").is_err());
    assert!(JobBinding::from_object_path(&unit, "/org/freedesktop/systemd1/job/17/extra").is_err());
    let mut changed_unit = valid.clone();
    changed_unit.unit = "other.service".to_owned();
    assert!(changed_unit.validate_for_request(&request).is_err());
    let mut changed_id = valid.clone();
    changed_id.job_id = 18;
    assert!(changed_id.validate_syntax_for_backend().is_err());
}

#[test]
fn pending_job_binding_is_durable_and_immutable_across_lifecycle()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir_in(std::env::current_dir()?)?;
    let path = directory.path().join("job-ledger.jsonl");
    let request = request("job-persist");
    let unit = unit_name(&request);
    let policy = job_policy();
    let binding = job(&unit, 23);
    let mut ledger = BrokerLedger::init(&path)?;
    assert!(ledger.reserve(&request, &unit, &policy)?);
    assert_eq!(ledger.pending_job_binding(&request, &policy)?, None);
    ledger.bind_job(&request, &policy, &binding)?;
    assert_eq!(
        ledger.pending_job_binding(&request, &policy)?,
        Some(binding.clone())
    );
    ledger.bind_job(&request, &policy, &binding)?;
    let mut changed = binding.clone();
    changed.job_id = 24;
    assert!(ledger.bind_job(&request, &policy, &changed).is_err());

    let receipt = LaunchReceipt {
        request: request.clone(),
        unit: unit.clone(),
        pid: 42,
        creation_token: "1234".to_owned(),
        executable: policy.executable.clone(),
        executable_sha256: policy.executable_sha256.clone(),
        uid: policy.target_uid,
        gid: policy.target_gid,
        capability_bounding_set: 0,
        ambient_capabilities: 0,
        control_group: format!("/system.slice/{unit}"),
        duplicate: false,
    };
    ledger.commit(&request, &receipt)?;
    assert_eq!(
        ledger.job_binding(&request, &policy)?,
        Some(binding.clone())
    );
    ledger.begin_stop(&request, &receipt)?;
    ledger.mark_stopped(&request, &receipt)?;
    assert_eq!(ledger.job_binding(&request, &policy)?, Some(binding));
    drop(ledger);
    let reopened = BrokerLedger::open(path)?;
    assert_eq!(
        reopened.job_binding(&request, &policy)?,
        Some(job(&unit, 23))
    );
    let legacy = serde_json::to_vec(&pending("legacy-nonce"))?;
    assert!(!String::from_utf8(legacy)?.contains("job"));
    Ok(())
}

#[test]
fn lifecycle_transition_cannot_replace_or_remove_a_retained_job() {
    let request = request("job-transition");
    let unit = unit_name(&request);
    let binding = job(&unit, 31);
    let mut records = vec![pending("job-transition")];
    records[0].job = Some(binding.clone());
    let policy = job_policy();
    records.push(LedgerRecord {
        request: request.clone(),
        unit: unit.clone(),
        identity: identity(),
        bootstrap: None,
        job: Some(binding.clone()),
        cancel_requested: None,
        state: LedgerState::Committed,
        receipt: Some(LaunchReceipt {
            request: request.clone(),
            unit: unit.clone(),
            pid: 42,
            creation_token: "1234".to_owned(),
            executable: policy.executable.clone(),
            executable_sha256: policy.executable_sha256.clone(),
            uid: policy.target_uid,
            gid: policy.target_gid,
            capability_bounding_set: 0,
            ambient_capabilities: 0,
            control_group: format!("/system.slice/{unit}"),
            duplicate: false,
        }),
    });
    let mut changed = records.clone();
    changed[1].job = None;
    assert!(parse_records(&encode(&changed)).is_err());
    let mut replaced = records;
    replaced[1].job = Some(job(&unit, 32));
    assert!(parse_records(&encode(&replaced)).is_err());
}

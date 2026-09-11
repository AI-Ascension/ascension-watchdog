//! Real subprocess/loopback tests for the test-only synthetic host.

use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fault_fixture::{Client, FaultPoint, Frame, MAX_RECEIPTS, RUNTIME_V3_SCHEMA_DIGEST};
use serde_json::{Value, json};
use uuid::Uuid;

struct RunningServer {
    child: OwnedChild,
    client: Client,
    database: PathBuf,
}

// Process lifetime is independent of the database: crash tests deliberately
// carry the same durable database into a replacement server.
struct OwnedChild(Child);

impl std::ops::Deref for OwnedChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.0
    }
}

impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

impl RunningServer {
    fn start(fault: FaultPoint) -> Result<Self, Box<dyn std::error::Error>> {
        let database =
            std::env::temp_dir().join(format!("watchdog-fault-fixture-{}.sqlite", Uuid::new_v4()));
        Self::start_on_database(database, fault)
    }

    fn start_on_database(
        database: PathBuf,
        fault: FaultPoint,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut child = OwnedChild(
            Command::new(env!("CARGO_BIN_EXE_fault-fixture-server"))
                .arg("--db")
                .arg(&database)
                .arg("--fault")
                .arg(fault.as_str())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()?,
        );
        let stdout = child.stdout.take().ok_or("server stdout unavailable")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let address = line
            .strip_prefix("LISTEN ")
            .ok_or("server did not announce its listener")?
            .trim()
            .parse::<SocketAddr>()?;
        Ok(Self {
            child,
            client: Client::new(address),
            database,
        })
    }

    fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.child.try_wait()?.is_none() {
            let _ = self
                .client
                .request(&Frame::request("shutdown", "recovery_read", json!({})));
        }
        let _ = self.child.wait_timeout(Duration::from_secs(2));
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
            let _ = self.child.wait();
        }
        remove_database(&self.database);
        Ok(())
    }
}

fn remove_database(path: &PathBuf) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = fs::remove_file(path.with_extension("sqlite-shm"));
    let _ = fs::remove_file(path.with_extension("sqlite.lock"));
}

#[test]
fn unwinding_reaps_the_child_but_preserves_restart_state() -> Result<(), Box<dyn std::error::Error>>
{
    let server = RunningServer::start(FaultPoint::None)?;
    let database = server.database;
    let client = server.client;
    let _ = bootstrap(&client)?;
    let child = server.child;
    let unwound = std::panic::catch_unwind(move || {
        let _owned_child = child;
        panic!("injected recovery test failure");
    });
    assert!(unwound.is_err());
    assert!(
        client
            .request(&Frame::request("stats", "recovery_read", json!({})))
            .is_err()
    );
    assert!(
        database.is_file(),
        "process cleanup must preserve durable state"
    );
    RunningServer::start_on_database(database, FaultPoint::None)?.stop()?;
    Ok(())
}

trait ChildWaitTimeout {
    fn wait_timeout(&mut self, timeout: Duration) -> Result<(), std::io::Error>;
}

impl ChildWaitTimeout for Child {
    fn wait_timeout(&mut self, timeout: Duration) -> Result<(), std::io::Error> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}

fn bootstrap(client: &Client) -> Result<(Value, Value, Value), Box<dyn std::error::Error>> {
    bootstrap_with_policy(client, 30, 10)
}

fn bootstrap_with_policy(
    client: &Client,
    ttl_seconds: i64,
    renewal_interval_seconds: i64,
) -> Result<(Value, Value, Value), Box<dyn std::error::Error>> {
    let boot_response = client.request(&Frame::request(
        "bootstrap_request",
        "bootstrap",
        json!({
            "deployment_id": Uuid::new_v4(),
            "instance_id": Uuid::new_v4(),
            "instance_incarnation": Uuid::new_v4(),
            "release": {
                "release_digest": digest("release"),
                "config_digest": digest("config"),
                "profile_digest": digest("profile"),
                "runtime_v3_schema_digest": RUNTIME_V3_SCHEMA_DIGEST
            },
            "lease_policy": {"ttl_seconds":ttl_seconds,"renewal_interval_seconds":renewal_interval_seconds}
        }),
    ))?;
    let boot = boot_response.payload["boot"].clone();
    let fence_response = client.request(&Frame::request(
        "host_fence_request",
        "host_fence",
        json!({"boot": boot}),
    ))?;
    let fence = fence_response.payload["fence"].clone();
    let lease_response = client.request(&Frame::request(
        "lease_acquire_request",
        "lease_acquire",
        json!({"boot": boot, "fence": fence}),
    ))?;
    Ok((boot, fence, lease_response.payload["lease"].clone()))
}

fn digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let mut result = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(&mut result, "{byte:02x}");
    }
    result
}

fn operation(lease: &Value, suffix: &str) -> (Value, Value) {
    let operation_id = Uuid::new_v4().to_string();
    // RCJ-1 canonical bytes are the payload identity. `suffix` is retained in
    // the test name/effect campaign, never smuggled into the action digest.
    let canonical_json = "{\"action\":{\"kind\":\"end_turn\"},\"action_id\":\"action-end-turn\"}";
    let canonical_json_b64 =
        "eyJhY3Rpb24iOnsia2luZCI6ImVuZF90dXJuIn0sImFjdGlvbl9pZCI6ImFjdGlvbi1lbmQtdHVybiJ9";
    let payload_digest = digest(canonical_json);
    let original_context = json!({
        "deployment_id": lease["deployment_id"], "instance_id": lease["instance_id"],
        "instance_incarnation": lease["instance_incarnation"], "boot_id": lease["boot_id"],
        "authority_generation": lease["authority_generation"], "lease_id": lease["lease_id"],
        "lease_epoch": lease["lease_epoch"]
    });
    let expected_boundary = json!({
        "state_id": Uuid::new_v4(), "generation": 1, "catalog_digest": digest("catalog")
    });
    let action = json!({
        "schema_digest": RUNTIME_V3_SCHEMA_DIGEST,
        "canonical_json_b64": canonical_json_b64,
        "payload_digest": payload_digest
    });
    let value = json!({
        "operation_id": operation_id, "payload_digest": payload_digest,
        "original_context": original_context, "expected_boundary": expected_boundary, "action": action
    });
    let reference = json!({
        "operation_id": value["operation_id"], "payload_digest": value["payload_digest"],
        "original_context": value["original_context"]
    });
    let _ = suffix;
    (value, reference)
}

fn submit_and_queue(
    client: &Client,
    lease: &Value,
    suffix: &str,
) -> Result<(Value, Value), Box<dyn std::error::Error>> {
    let (full, reference) = operation(lease, suffix);
    client.request(&Frame::request(
        "operation_intent_request",
        "operation_submit",
        json!({"lease":lease,"operation":full}),
    ))?;
    client.request(&Frame::request(
        "operation_dispatch_request",
        "operation_submit",
        json!({"lease":lease,"operation":reference.clone()}),
    ))?;
    Ok((full, reference))
}

#[test]
fn response_loss_keeps_effect_witness_and_client_uncertainty()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::ResponseLoss)?;
    let (client, database) = (server.client, server.database.clone());
    let (_boot, _fence, lease) = bootstrap(&client)?;
    let (full, reference) = submit_and_queue(&client, &lease, "response-loss")?;
    let tick = Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    );
    let lost = client.request(&tick);
    assert!(lost.is_err(), "the injected response must be unavailable");
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 1);
    assert_eq!(stats.payload["receipt_count"], 1);
    let lookup = client.request(&Frame::request(
        "operation_lookup_request",
        "recovery_read",
        json!({"operation":reference,"lookup_scope":"historical_read"}),
    ))?;
    assert_eq!(lookup.payload["mutation_authorized"], false);
    assert_eq!(lookup.payload["operation"]["state"], "SETTLED");
    assert_eq!(
        lookup.payload["operation"]["witness"]["operation_id"],
        full["operation_id"]
    );
    let _ = client.request(&Frame::request("shutdown", "recovery_read", json!({})));
    let mut child = server.child;
    let _ = child.wait();
    remove_database(&database);
    Ok(())
}

#[test]
fn lookup_rejects_a_reference_with_the_wrong_original_context()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::None)?;
    let client = server.client;
    let (_boot, _fence, lease) = bootstrap(&client)?;
    let (_full, mut reference) = submit_and_queue(&client, &lease, "wrong-context-lookup")?;
    reference["original_context"]["instance_id"] = json!(Uuid::new_v4());

    let lookup = client.request(&Frame::request(
        "operation_lookup_request",
        "recovery_read",
        json!({"operation":reference,"lookup_scope":"historical_read"}),
    ))?;
    assert_eq!(lookup.payload["result"]["status"], "CONFLICT");
    assert!(lookup.payload["operation"].is_null());
    server.stop()?;
    Ok(())
}

#[test]
fn reconcile_rejects_a_reference_with_the_wrong_original_context()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::AfterMutation)?;
    let client = server.client;
    let database = server.database.clone();
    let (_boot, _fence, old_lease) = bootstrap(&client)?;
    let (full, mut reference) = submit_and_queue(&client, &old_lease, "wrong-context-reconcile")?;
    let tick = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ));
    assert!(tick.is_err(), "after-mutation crash must drop the response");
    let mut crashed = server.child;
    assert_eq!(crashed.wait()?.code(), Some(70));

    let restarted = RunningServer::start_on_database(database.clone(), FaultPoint::None)?;
    let restarted_client = restarted.client;
    let (_new_boot, replacement_fence, _new_lease) = bootstrap(&restarted_client)?;
    reference["original_context"]["instance_id"] = json!(Uuid::new_v4());
    let reconciled = restarted_client.request(&Frame::request(
        "operation_reconcile_request",
        "recovery_reconcile",
        json!({"operation":reference,"strategy":"receipt_lookup","current_fence":replacement_fence}),
    ))?;
    assert_eq!(reconciled.payload["result"]["status"], "CONFLICT");
    assert!(reconciled.payload["operation"].is_null());
    assert!(reconciled.payload["witness"].is_null());

    let connection = rusqlite::Connection::open(&database)?;
    let state: String = connection.query_row(
        "SELECT state FROM operations WHERE operation_id=?1",
        [full["operation_id"].as_str().ok_or("operation id")?],
        |row| row.get(0),
    )?;
    assert_eq!(state, "UNKNOWN");
    drop(connection);
    RunningServer {
        child: restarted.child,
        client: restarted_client,
        database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn malformed_response_does_not_erase_the_durable_receipt() -> Result<(), Box<dyn std::error::Error>>
{
    let server = RunningServer::start(FaultPoint::MalformedResponse)?;
    let client = server.client;
    let (full, _fence, _lease) = {
        let (_boot, fence, lease) = bootstrap(&client)?;
        let (full, _reference) = submit_and_queue(&client, &lease, "malformed-response")?;
        (full, fence, lease)
    };
    let tick = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ));
    assert!(
        tick.is_err(),
        "the injected malformed response must not parse"
    );
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 1);
    assert_eq!(stats.payload["receipt_count"], 1);
    RunningServer {
        child: server.child,
        client,
        database: server.database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn stale_queued_fence_is_rejected_without_an_effect() -> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::None)?;
    let client = server.client;
    let (_boot, _fence, lease) = bootstrap(&client)?;
    let (full, reference) = submit_and_queue(&client, &lease, "stale-queued")?;
    let (_replacement_boot, _replacement_fence, _replacement_lease) = bootstrap(&client)?;
    let response = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ))?;
    assert_eq!(response.payload["result"]["status"], "NOT_FOUND");
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 0);
    assert_eq!(stats.payload["queue_count"], 0);
    let lookup = client.request(&Frame::request(
        "operation_lookup_request",
        "recovery_read",
        json!({"operation":reference,"lookup_scope":"historical_read"}),
    ))?;
    assert_eq!(lookup.payload["operation"]["state"], "UNKNOWN");
    RunningServer {
        child: server.child,
        client,
        database: server.database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn conflicting_expected_boundary_reuse_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::None)?;
    let client = server.client;
    let (_boot, _fence, lease) = bootstrap(&client)?;
    let (original, _reference) = operation(&lease, "boundary-conflict");
    let first = client.request(&Frame::request(
        "operation_intent_request",
        "operation_submit",
        json!({"lease":lease,"operation":original}),
    ))?;
    assert_eq!(first.payload["result"]["status"], "INTENT_RECORDED");

    let mut conflicting = original;
    conflicting["expected_boundary"]["generation"] = json!(2);
    let second = client.request(&Frame::request(
        "operation_intent_request",
        "operation_submit",
        json!({"lease":lease,"operation":conflicting}),
    ))?;
    assert_eq!(
        second.payload["result"]["status"], "CONFLICT",
        "operation identity must include the immutable expected boundary"
    );
    RunningServer {
        child: server.child,
        client,
        database: server.database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn crash_after_admission_is_quarantined_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::AfterAdmission)?;
    let client = server.client;
    let database = server.database.clone();
    let (_boot, _fence, lease) = bootstrap(&client)?;
    let (full, reference) = operation(&lease, "crash-after-admission");
    client.request(&Frame::request(
        "operation_intent_request",
        "operation_submit",
        json!({"lease":lease,"operation":full}),
    ))?;
    let dispatch = client.request(&Frame::request(
        "operation_dispatch_request",
        "operation_submit",
        json!({"lease":lease,"operation":reference.clone()}),
    ));
    assert!(
        dispatch.is_err(),
        "after-admission crash must drop the response"
    );
    let mut crashed = server.child;
    let exit = crashed.wait()?;
    assert_eq!(exit.code(), Some(70));
    let restarted = RunningServer::start_on_database(database.clone(), FaultPoint::None)?;
    let client = restarted.client;
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["queue_count"], 0);
    assert_eq!(stats.payload["effect_count"], 0);
    assert_eq!(stats.payload["unresolved_count"], 1);
    let lookup = client.request(&Frame::request(
        "operation_lookup_request",
        "recovery_read",
        json!({
            "operation": reference,
            "lookup_scope": "historical_read"
        }),
    ))?;
    assert_eq!(lookup.payload["operation"]["state"], "UNKNOWN");
    let tick = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ))?;
    assert_eq!(tick.payload["result"]["status"], "NOT_FOUND");
    RunningServer {
        child: restarted.child,
        client,
        database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn crash_after_mutation_retains_witness_without_receipt_or_second_effect()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::AfterMutation)?;
    let client = server.client;
    let database = server.database.clone();
    let (_boot, _fence, lease) = bootstrap(&client)?;
    let (full, reference) = submit_and_queue(&client, &lease, "crash-after-mutation")?;
    let tick = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ));
    assert!(tick.is_err(), "after-mutation crash must drop the response");
    let mut crashed = server.child;
    let exit = crashed.wait()?;
    assert_eq!(exit.code(), Some(70));
    let restarted = RunningServer::start_on_database(database.clone(), FaultPoint::None)?;
    let client = restarted.client;
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 1);
    assert_eq!(stats.payload["receipt_count"], 0);
    assert_eq!(stats.payload["unresolved_count"], 1);
    let (_replacement_boot, replacement_fence, _replacement_lease) = bootstrap(&client)?;
    let reconciled = client.request(&Frame::request(
        "operation_reconcile_request",
        "recovery_reconcile",
        json!({"operation":reference,"strategy":"receipt_lookup","current_fence":replacement_fence}),
    ))?;
    assert_eq!(reconciled.payload["result"]["status"], "RECONCILED");
    assert_eq!(
        reconciled.payload["witness"]["operation_id"],
        full["operation_id"]
    );
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 1);
    RunningServer {
        child: restarted.child,
        client,
        database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn receipt_capacity_backpressures_the_sixty_fifth_operation()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::None)?;
    let client = server.client;
    let (_boot, _fence, lease) = bootstrap(&client)?;
    for index in 0..MAX_RECEIPTS {
        let (full, _reference) = submit_and_queue(&client, &lease, &format!("receipt-{index}"))?;
        let response = client.request(&Frame::request(
            "host_tick",
            "recovery_reconcile",
            json!({"operation_id":full["operation_id"]}),
        ))?;
        assert_eq!(response.payload["result"]["status"], "SETTLED");
    }
    let (full, reference) = submit_and_queue(&client, &lease, "receipt-overflow")?;
    let response = client.request(&Frame::request(
        "operation_dispatch_request",
        "operation_submit",
        json!({"lease":lease,"operation":reference}),
    ))?;
    assert_eq!(response.payload["result"]["status"], "BOUNDS_EXCEEDED");
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["receipt_count"], MAX_RECEIPTS);
    assert_eq!(stats.payload["effect_count"], MAX_RECEIPTS);
    assert_eq!(stats.payload["queue_count"], 0);
    let _ = full;
    RunningServer {
        child: server.child,
        client,
        database: server.database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn queued_ticket_deadline_is_immutable_across_lease_renewals()
-> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::None)?;
    let client = server.client;
    let (_boot, _fence, lease) = bootstrap_with_policy(&client, 12, 4)?;
    let (full, reference) = submit_and_queue(&client, &lease, "immutable-ticket-expiry")?;

    let mut renewed = lease.clone();
    for sequence in 1..=3 {
        let response = client.request(&Frame::request(
            "lease_renew_request",
            "lease_renew",
            json!({"lease":renewed,"renew_sequence":sequence}),
        ))?;
        assert_eq!(response.payload["result"]["status"], "LEASE_RENEWED");
        renewed = response.payload["lease"].clone();
    }
    assert_eq!(renewed["expires_at"], "2026-09-06T00:00:24Z");

    let tick = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ))?;
    assert_eq!(tick.payload["result"]["status"], "LEASE_EXPIRED");
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 0);
    assert_eq!(stats.payload["queue_count"], 0);
    let lookup = client.request(&Frame::request(
        "operation_lookup_request",
        "recovery_read",
        json!({"operation":reference,"lookup_scope":"historical_read"}),
    ))?;
    assert_eq!(lookup.payload["operation"]["state"], "UNKNOWN");
    assert_eq!(
        lookup.payload["operation"]["ticket"]["expires_at"],
        "2026-09-06T00:00:12Z"
    );
    assert_eq!(
        lookup.payload["operation"]["uncertainty_reason"],
        "authority_rotated"
    );
    RunningServer {
        child: server.child,
        client,
        database: server.database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn revoked_queued_ticket_is_unknown_before_queue_removal() -> Result<(), Box<dyn std::error::Error>>
{
    let server = RunningServer::start(FaultPoint::None)?;
    let client = server.client;
    let (_boot, _fence, lease) = bootstrap(&client)?;
    let (full, reference) = submit_and_queue(&client, &lease, "revoked-ticket")?;
    let revoked = client.request(&Frame::request(
        "lease_revoke_request",
        "lease_revoke",
        json!({"lease":lease,"reason":"operator"}),
    ))?;
    assert_eq!(revoked.payload["result"]["status"], "LEASE_REVOKED");

    let tick = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ))?;
    assert_eq!(tick.payload["result"]["status"], "LEASE_EXPIRED");
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 0);
    assert_eq!(stats.payload["queue_count"], 0);
    let lookup = client.request(&Frame::request(
        "operation_lookup_request",
        "recovery_read",
        json!({"operation":reference,"lookup_scope":"historical_read"}),
    ))?;
    assert_eq!(lookup.payload["operation"]["state"], "UNKNOWN");
    assert_ne!(lookup.payload["operation"]["state"], "REJECTED");
    RunningServer {
        child: server.child,
        client,
        database: server.database,
    }
    .stop()?;
    Ok(())
}

#[test]
fn lease_policy_and_epoch_history_survive_restart() -> Result<(), Box<dyn std::error::Error>> {
    let server = RunningServer::start(FaultPoint::None)?;
    let client = server.client;
    let database = server.database.clone();
    let (old_boot, _old_fence, first) = bootstrap_with_policy(&client, 12, 4)?;
    assert_eq!(first["ttl_seconds"], 12);
    assert_eq!(first["renewal_interval_seconds"], 4);
    let renewed = client.request(&Frame::request(
        "lease_renew_request",
        "lease_renew",
        json!({"lease":first,"renew_sequence":1}),
    ))?;
    assert_eq!(
        renewed.payload["lease"]["expires_at"],
        "2026-09-06T00:00:16Z"
    );
    let connection = rusqlite::Connection::open(&database)?;
    let history: (i64, i64, i64, i64) = connection.query_row(
        "SELECT lease_epoch,ttl_seconds,renewal_interval_seconds,renew_sequence FROM lease_history",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(history, (1, 12, 4, 1));
    drop(connection);

    let mut crashed = server.child;
    crashed.kill()?;
    let _ = crashed.wait()?;
    let restarted = RunningServer::start_on_database(database.clone(), FaultPoint::None)?;
    let fenced = restarted.client.request(&Frame::request(
        "host_fence_request",
        "host_fence",
        json!({"boot":old_boot}),
    ))?;
    assert_eq!(fenced.payload["result"]["status"], "HOST_NOT_READY");
    let (_boot, _fence, second) = bootstrap_with_policy(&restarted.client, 20, 5)?;
    assert_eq!(second["lease_epoch"], 2);
    assert_eq!(second["ttl_seconds"], 20);
    let connection = rusqlite::Connection::open(&database)?;
    let durable: (i64, i64, i64) = connection.query_row(
        "SELECT COUNT(*),MAX(lease_epoch),MAX(lease_epoch_counter) FROM lease_history CROSS JOIN fence",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(durable, (2, 2, 2));
    drop(connection);
    restarted.stop()?;
    Ok(())
}

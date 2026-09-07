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
            "lease_policy": {"ttl_seconds":30,"renewal_interval_seconds":10}
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
    let (_boot, fence, lease) = bootstrap(&client)?;
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
    let _ = fence;
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
    let (full, _reference) = submit_and_queue(&client, &lease, "stale-queued")?;
    let (_replacement_boot, _replacement_fence, _replacement_lease) = bootstrap(&client)?;
    let response = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ))?;
    assert_eq!(response.payload["result"]["status"], "STALE_LEASE");
    let stats = client.request(&Frame::request("stats", "recovery_read", json!({})))?;
    assert_eq!(stats.payload["effect_count"], 0);
    assert_eq!(stats.payload["queue_count"], 0);
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
fn crash_after_admission_survives_restart_and_executes_the_queued_operation()
-> Result<(), Box<dyn std::error::Error>> {
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
    assert_eq!(stats.payload["queue_count"], 1);
    assert_eq!(stats.payload["effect_count"], 0);
    let tick = client.request(&Frame::request(
        "host_tick",
        "recovery_reconcile",
        json!({"operation_id":full["operation_id"]}),
    ))?;
    assert_eq!(tick.payload["result"]["status"], "SETTLED");
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
    let (_boot, fence, lease) = bootstrap(&client)?;
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
    let reconciled = client.request(&Frame::request(
        "operation_reconcile_request",
        "recovery_reconcile",
        json!({"operation":reference,"strategy":"receipt_lookup","current_fence":fence}),
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

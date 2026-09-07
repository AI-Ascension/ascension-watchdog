use ascension_watchdog::worker_protocol::{
    EMPTY_PARAMETERS_DIGEST, Frame, MAX_FRAME_BYTES, ProtocolError, SCHEMA_DIGEST,
    canonical_parameters, decode_frame, decode_request, decode_response, encode_frame, sha256_hex,
};
use serde_json::Value;

const SCHEMA_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../worker-handoff-v1/schema.json"
));
const MANIFEST_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../worker-handoff-v1/manifest.json"
));

fn valid_fixture(name: &str) -> &'static [u8] {
    match name {
        "probe-request" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/probe-request.json"
        )),
        "probe-response" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/probe-response.json"
        )),
        "dispatch" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/dispatch.json"
        )),
        "dispatch-response" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/dispatch-response.json"
        )),
        "lookup-request" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/lookup-request.json"
        )),
        "acknowledge-request" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/acknowledge-request.json"
        )),
        "control-request" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/control-request.json"
        )),
        "control-response" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/valid/control-response.json"
        )),
        _ => panic!("unknown valid worker handoff fixture {name}"),
    }
}

fn invalid_fixture(name: &str) -> &'static [u8] {
    match name {
        "duplicate-field" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/duplicate-field.json"
        )),
        "unknown-field" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/unknown-field.json"
        )),
        "depth" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/depth.json"
        )),
        "oversized-frame" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/oversized-frame.json"
        )),
        "scope-mismatch" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/scope-mismatch.json"
        )),
        "no-job-tuple" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/no-job-tuple.json"
        )),
        "parameters-not-empty" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/parameters-not-empty.json"
        )),
        "handoff-not-uuid4" => include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../worker-handoff-v1/fixtures/invalid/handoff-not-uuid4.json"
        )),
        _ => panic!("unknown invalid worker handoff fixture {name}"),
    }
}

#[test]
fn schema_manifest_and_rust_digest_are_identical() {
    let manifest: Value = serde_json::from_slice(MANIFEST_BYTES).expect("valid manifest JSON");
    let manifest_digest = manifest
        .get("schema_digest")
        .and_then(Value::as_str)
        .expect("manifest schema digest");
    assert_eq!(sha256_hex(SCHEMA_BYTES), SCHEMA_DIGEST);
    assert_eq!(manifest_digest, SCHEMA_DIGEST);
    assert_eq!(
        manifest.get("schema_file").and_then(Value::as_str),
        Some("schema.json")
    );
}

#[test]
fn valid_fixtures_decode_and_round_trip() {
    for name in [
        "probe-request",
        "probe-response",
        "dispatch",
        "dispatch-response",
        "lookup-request",
        "acknowledge-request",
        "control-request",
        "control-response",
    ] {
        let frame = decode_frame(valid_fixture(name)).expect(name);
        let encoded = encode_frame(&frame).expect(name);
        assert_eq!(decode_frame(&encoded).expect(name), frame);
    }
    assert!(matches!(
        decode_request(valid_fixture("dispatch")),
        Ok(Frame::DispatchRequest(_))
    ));
    assert!(matches!(
        decode_response(valid_fixture("dispatch-response")),
        Ok(Frame::DispatchResponse(_))
    ));
}

#[test]
fn invalid_fixtures_fail_closed() {
    for name in [
        "duplicate-field",
        "unknown-field",
        "depth",
        "oversized-frame",
        "scope-mismatch",
        "no-job-tuple",
        "parameters-not-empty",
        "handoff-not-uuid4",
    ] {
        let error = decode_frame(invalid_fixture(name)).expect_err(name);
        assert!(!matches!(error, ProtocolError::InvalidSchema(message) if message.is_empty()));
    }
    assert!(invalid_fixture("oversized-frame").len() > MAX_FRAME_BYTES);
}

#[test]
fn handoff_id_is_an_independent_uuid_not_a_derived_digest() {
    let mut value: Value =
        serde_json::from_slice(valid_fixture("dispatch")).expect("dispatch JSON");
    value["handoff_id"] = Value::String("99999999-9999-4999-8999-999999999999".to_owned());
    let bytes = serde_json::to_vec(&value).expect("mutated dispatch JSON");
    assert!(decode_frame(&bytes).is_ok());
}

#[test]
fn runtime_v3_payload_is_exactly_empty_and_digest_bound() {
    let empty = serde_json::json!({});
    assert_eq!(
        canonical_parameters(&empty).expect("empty parameters"),
        b"{}"
    );
    assert_eq!(sha256_hex(b"{}"), EMPTY_PARAMETERS_DIGEST);
    assert!(canonical_parameters(&serde_json::json!({"seed": 7})).is_err());
    assert!(canonical_parameters(&serde_json::json!(null)).is_err());
}

#[test]
fn dispatch_requires_a_positive_acknowledged_mode_sequence() {
    let mut value: Value =
        serde_json::from_slice(valid_fixture("dispatch")).expect("dispatch JSON");
    value["mode_sequence"] = Value::from(0_u64);
    let bytes = serde_json::to_vec(&value).expect("mutated dispatch JSON");
    assert!(matches!(
        decode_frame(&bytes),
        Err(ProtocolError::InvalidNumber(message)) if message.contains("mode_sequence")
    ));
}

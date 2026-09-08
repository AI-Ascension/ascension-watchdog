use ascension_watchdog::worker_bootstrap::{
    BootstrapError, ExpectedPeer, FRAME_PREFIX_BYTES, LinuxPeer, MAGIC, MAX_FRAME_BYTES,
    MAX_PAYLOAD_BYTES, WindowsPeer, WorkerBootstrap, decode_frame, encode_frame,
};
use serde_json::{Value, json};
use uuid::Uuid;

const LAUNCH_NONCE: &str = "abcdefab-cdef-4abc-8def-abcdefabcdef";
const WATCHDOG_BOOT_ID: &str = "22222222-2222-4222-8222-222222222222";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn linux_frame() -> WorkerBootstrap {
    WorkerBootstrap::linux(
        Uuid::parse_str(LAUNCH_NONCE).unwrap(),
        Uuid::parse_str(WATCHDOG_BOOT_ID).unwrap(),
        "worker.main",
        LinuxPeer::new(
            42,
            "18446744073709551615",
            "/opt/ascension/worker",
            DIGEST,
            1000,
            1000,
        )
        .unwrap(),
    )
    .unwrap()
}

fn windows_frame() -> WorkerBootstrap {
    WorkerBootstrap::windows(
        Uuid::parse_str(LAUNCH_NONCE).unwrap(),
        Uuid::parse_str(WATCHDOG_BOOT_ID).unwrap(),
        "worker-main",
        WindowsPeer::new(
            42,
            "132456789012345678",
            r"C:\Program Files\Ascension\worker.exe",
            DIGEST,
            1,
            "S-1-5-21-100-200-300-1001",
        )
        .unwrap(),
    )
    .unwrap()
}

fn payload_frame(value: &Value) -> Vec<u8> {
    let payload = serde_json::to_vec(value).unwrap();
    assert!(payload.len() <= MAX_PAYLOAD_BYTES);
    let mut frame = Vec::with_capacity(FRAME_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn linux_payload() -> Value {
    json!({
        "version": 1,
        "launch_nonce": LAUNCH_NONCE,
        "watchdog_boot_id": WATCHDOG_BOOT_ID,
        "component_id": "worker.main",
        "expected_peer": {
            "platform": "linux",
            "pid": 42,
            "creation_token": "18446744073709551615",
            "executable": "/opt/ascension/worker",
            "executable_sha256": DIGEST,
            "uid": 1000,
            "gid": 1000,
        }
    })
}

fn windows_payload() -> Value {
    json!({
        "version": 1,
        "launch_nonce": LAUNCH_NONCE,
        "watchdog_boot_id": WATCHDOG_BOOT_ID,
        "component_id": "worker-main",
        "expected_peer": {
            "platform": "windows",
            "pid": 42,
            "creation_token": "132456789012345678",
            "executable": r"C:\Program Files\Ascension\worker.exe",
            "executable_sha256": DIGEST,
            "session_id": 1,
            "sid": "S-1-5-21-100-200-300-1001",
        }
    })
}

#[test]
fn linux_and_windows_frames_round_trip() {
    let linux = linux_frame();
    let encoded = encode_frame(&linux).unwrap();
    assert_eq!(
        encoded.len(),
        FRAME_PREFIX_BYTES
            + u32::from_be_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]) as usize
    );
    assert_eq!(decode_frame(&encoded).unwrap(), linux);

    let windows = windows_frame();
    assert_eq!(
        decode_frame(&encode_frame(&windows).unwrap()).unwrap(),
        windows
    );
}

#[test]
fn framing_rejects_magic_lengths_truncation_and_trailing_bytes() {
    let encoded = encode_frame(&linux_frame()).unwrap();

    let mut wrong_magic = encoded.clone();
    wrong_magic[0] = b'X';
    assert_eq!(
        decode_frame(&wrong_magic),
        Err(BootstrapError::InvalidMagic)
    );

    assert_eq!(
        decode_frame(&encoded[..FRAME_PREFIX_BYTES - 1]),
        Err(BootstrapError::Truncated)
    );

    let mut zero_length = encoded.clone();
    zero_length[8..12].copy_from_slice(&0_u32.to_be_bytes());
    assert_eq!(
        decode_frame(&zero_length),
        Err(BootstrapError::InvalidLength)
    );

    let mut oversized_length = encoded.clone();
    oversized_length[8..12]
        .copy_from_slice(&u32::try_from(MAX_PAYLOAD_BYTES + 1).unwrap().to_be_bytes());
    assert_eq!(
        decode_frame(&oversized_length),
        Err(BootstrapError::InvalidLength)
    );

    let mut truncated = encoded.clone();
    truncated.pop();
    assert_eq!(decode_frame(&truncated), Err(BootstrapError::Truncated));

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(decode_frame(&trailing), Err(BootstrapError::TrailingBytes));

    let too_large = vec![0_u8; MAX_FRAME_BYTES + 1];
    assert_eq!(decode_frame(&too_large), Err(BootstrapError::FrameTooLarge));
}

#[test]
fn strict_deserializer_rejects_invalid_utf8_duplicates_and_unknown_fields() {
    let valid = serde_json::to_vec(&linux_payload()).unwrap();
    let mut invalid_utf8 = valid.clone();
    invalid_utf8[0] = 0xff;
    assert_eq!(
        decode_frame(&payload_bytes(&invalid_utf8)),
        Err(BootstrapError::InvalidJson)
    );

    let duplicate = br#"{"version":1,"launch_nonce":"abcdefab-cdef-4abc-8def-abcdefabcdef","watchdog_boot_id":"22222222-2222-4222-8222-222222222222","component_id":"worker.main","component_id":"worker.main","expected_peer":{}}"#;
    assert_eq!(
        decode_frame(&payload_bytes(duplicate)),
        Err(BootstrapError::InvalidJson)
    );

    let mut unknown = linux_payload();
    unknown["unexpected"] = Value::Bool(true);
    assert_eq!(
        decode_frame(&payload_frame(&unknown)),
        Err(BootstrapError::InvalidSchema)
    );

    let nested_unknown = json!({
        "version": 1,
        "launch_nonce": LAUNCH_NONCE,
        "watchdog_boot_id": WATCHDOG_BOOT_ID,
        "component_id": "worker.main",
        "expected_peer": {
            "platform": "linux", "pid": 42, "creation_token": "1",
            "executable": "/worker", "executable_sha256": DIGEST,
            "uid": 0, "gid": 0, "extra": false
        }
    });
    assert_eq!(
        decode_frame(&payload_frame(&nested_unknown)),
        Err(BootstrapError::InvalidSchema)
    );
}

#[test]
fn uuid_component_and_digest_policy_is_closed_and_canonical() {
    let mut payload = linux_payload();
    payload["launch_nonce"] = Value::String(LAUNCH_NONCE.to_ascii_uppercase());
    assert_eq!(
        decode_frame(&payload_frame(&payload)),
        Err(BootstrapError::InvalidUuid)
    );

    let mut payload = linux_payload();
    payload["launch_nonce"] = Value::String("abcdefabcdef4abc8defabcdefabcdef".to_owned());
    assert_eq!(
        decode_frame(&payload_frame(&payload)),
        Err(BootstrapError::InvalidUuid)
    );

    let mut payload = linux_payload();
    payload["component_id"] = Value::String(".".to_owned());
    assert_eq!(
        decode_frame(&payload_frame(&payload)),
        Err(BootstrapError::InvalidComponent)
    );

    let mut payload = linux_payload();
    payload["component_id"] = Value::String("x".repeat(129));
    assert_eq!(
        decode_frame(&payload_frame(&payload)),
        Err(BootstrapError::InvalidComponent)
    );

    let mut payload = linux_payload();
    payload["expected_peer"]["executable_sha256"] = Value::String("A".repeat(64));
    assert_eq!(
        decode_frame(&payload_frame(&payload)),
        Err(BootstrapError::InvalidDigest)
    );
}

#[test]
fn creation_tokens_are_positive_canonical_decimal_u64() {
    for token in ["0", "01", "18446744073709551616", "123456789012345678901"] {
        let mut payload = linux_payload();
        payload["expected_peer"]["creation_token"] = Value::String(token.to_owned());
        assert_eq!(
            decode_frame(&payload_frame(&payload)),
            Err(BootstrapError::InvalidToken),
            "token {token}"
        );
    }

    let mut payload = linux_payload();
    payload["expected_peer"]["creation_token"] = Value::String("1".to_owned());
    assert_eq!(
        decode_frame(&payload_frame(&payload))
            .unwrap()
            .expected_peer,
        ExpectedPeer::Linux(LinuxPeer {
            pid: 42,
            creation_token: "1".to_owned(),
            executable: "/opt/ascension/worker".to_owned(),
            executable_sha256: DIGEST.to_owned(),
            uid: 1000,
            gid: 1000,
        })
    );
}

#[test]
fn platform_paths_have_their_declared_forms_and_byte_limits() {
    let mut linux = linux_payload();
    linux["expected_peer"]["executable"] = Value::String("relative/worker".to_owned());
    assert_eq!(
        decode_frame(&payload_frame(&linux)),
        Err(BootstrapError::InvalidPath)
    );

    let mut linux = linux_payload();
    linux["expected_peer"]["executable"] = Value::String(format!("/{}", "x".repeat(4096)));
    assert_eq!(
        decode_frame(&payload_frame(&linux)),
        Err(BootstrapError::InvalidPath)
    );

    let mut windows = windows_payload();
    windows["expected_peer"]["executable"] = Value::String(r"\\server\worker.exe".to_owned());
    assert_eq!(
        decode_frame(&payload_frame(&windows)),
        Err(BootstrapError::InvalidPath)
    );

    let windows = json!({
        "version": 1, "launch_nonce": LAUNCH_NONCE,
        "watchdog_boot_id": WATCHDOG_BOOT_ID, "component_id": "worker-main",
        "expected_peer": {
            "platform": "windows", "pid": 42, "creation_token": "1",
            "executable": format!(r"C:\{}", "x".repeat(4094)),
            "executable_sha256": DIGEST, "session_id": 1,
            "sid": "S-1-5-21-100-200-300-1001"
        }
    });
    assert_eq!(
        decode_frame(&payload_frame(&windows)),
        Err(BootstrapError::InvalidPath)
    );
}

#[test]
fn numeric_sid_is_canonical_and_bounded() {
    for sid in [
        "S-1-5",
        "S-1-281474976710656-1",
        "S-1-5-01",
        "S-1-5-4294967296",
        "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
    ] {
        let mut payload = windows_payload();
        payload["expected_peer"]["sid"] = Value::String(sid.to_owned());
        assert_eq!(
            decode_frame(&payload_frame(&payload)),
            Err(BootstrapError::InvalidPeer),
            "sid {sid}"
        );
    }

    let mut payload = windows_payload();
    payload["expected_peer"]["sid"] =
        Value::String("S-1-281474976710655-4294967295-0-1".to_owned());
    assert!(decode_frame(&payload_frame(&payload)).is_ok());
}

fn payload_bytes(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() <= MAX_PAYLOAD_BYTES);
    let mut frame = Vec::with_capacity(FRAME_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn version_four_bits_do_not_authorize_non_rfc_uuid_variants() {
    for variant in ['0', '7', 'c', 'e', 'f'] {
        let invalid = format!("abcdefab-cdef-4abc-{variant}def-abcdefabcdef");
        for field in ["launch_nonce", "watchdog_boot_id"] {
            let mut payload = linux_payload();
            payload[field] = Value::String(invalid.clone());
            assert_eq!(
                decode_frame(&payload_frame(&payload)),
                Err(BootstrapError::InvalidUuid),
                "{field}: {invalid}"
            );
            let mut typed = linux_frame();
            let uuid = Uuid::parse_str(&invalid).expect("syntactically valid UUID");
            if field == "launch_nonce" {
                typed.launch_nonce = uuid;
            } else {
                typed.watchdog_boot_id = uuid;
            }
            assert_eq!(encode_frame(&typed), Err(BootstrapError::InvalidUuid));
        }
    }
}

#[test]
fn escaped_duplicate_peer_keys_are_rejected_before_typed_conversion() {
    let valid =
        String::from_utf8(serde_json::to_vec(&linux_payload()).expect("JSON")).expect("UTF-8");
    for duplicate in [r#""pid":42,"pid":42"#, r#""pid":42,"p\u0069d":42"#] {
        let payload = valid.replace(r#""pid":42"#, duplicate);
        assert_ne!(payload, valid);
        assert_eq!(
            decode_frame(&payload_bytes(payload.as_bytes())),
            Err(BootstrapError::InvalidJson)
        );
    }
}

#[test]
fn owner_published_linux_and_windows_payloads_decode_without_rewriting() {
    for payload in [
        include_bytes!("../../../schemas/worker-bootstrap-v1/valid/linux.json").as_slice(),
        include_bytes!("../../../schemas/worker-bootstrap-v1/valid/windows.json").as_slice(),
    ] {
        let decoded = decode_frame(&payload_bytes(payload)).expect("owner fixture");
        assert_eq!(decoded.component_id, "harness");
        assert_eq!(
            decode_frame(&encode_frame(&decoded).expect("encode")),
            Ok(decoded)
        );
    }
}

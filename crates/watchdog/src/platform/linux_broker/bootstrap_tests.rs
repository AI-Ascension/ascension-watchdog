use super::*;
use crate::platform::gateway_health::{FRAME_BYTES as HEALTH_FRAME_BYTES, GatewayHealthBootstrap};
use crate::worker_bootstrap::{
    LinuxPeer, WindowsPeer, WorkerBootstrap, WorkerBootstrapLaunch, encode_frame,
};
use serde_json::json;
use uuid::Uuid;

const NONCE: &str = "11111111-1111-4111-8111-111111111111";
const BOOT: &str = "22222222-2222-4222-8222-222222222222";
const OTHER_NONCE: &str = "33333333-3333-4333-8333-333333333333";
const OTHER_BOOT: &str = "44444444-4444-4444-8444-444444444444";

fn uuid(value: &str) -> Uuid {
    Uuid::parse_str(value).expect("test UUID is valid")
}

fn make_request(component: BrokerComponent, instance: &str, nonce: &str) -> BrokerRequest {
    BrokerRequest {
        component,
        instance: instance.to_owned(),
        incarnation: "incarnation-1".to_owned(),
        nonce: nonce.to_owned(),
    }
}

fn gateway(request: &BrokerRequest) -> GatewayHealthBootstrap {
    GatewayHealthBootstrap::new(uuid(&request.nonce), [0xa5_u8; 32])
        .expect("test Gateway health bootstrap is valid")
}

fn linux_peer() -> LinuxPeer {
    LinuxPeer::new(17, "123", "/usr/bin/harness", "a".repeat(64), 1000, 1000)
        .expect("test Linux peer is valid")
}

fn worker(request: &BrokerRequest, boot: &str, component_id: &str) -> WorkerBootstrapLaunch {
    let frame =
        WorkerBootstrap::linux(uuid(&request.nonce), uuid(boot), component_id, linux_peer())
            .expect("test worker bootstrap is valid");
    WorkerBootstrapLaunch::new(frame).expect("test worker frame is encodable")
}

fn make_binding(kind: BootstrapKind, boot: &str, frame: &[u8]) -> BrokerBootstrapBinding {
    BrokerBootstrapBinding {
        version: BOOTSTRAP_BINDING_VERSION,
        kind,
        watchdog_boot_id: boot.to_owned(),
        frame_sha256: sha256_hex(frame),
    }
}

#[test]
fn exact_gateway_and_worker_frames_are_bound_without_reencoding() {
    let gateway_request = make_request(BrokerComponent::Gateway, "gateway", NONCE);
    let gateway_frame = gateway(&gateway_request);
    let gateway_encoded = gateway_frame.encoded_frame();
    let gateway_launch = BrokerBootstrapLaunch::for_gateway(&gateway_request, BOOT, &gateway_frame)
        .expect("Gateway launch binding should succeed");
    assert_eq!(gateway_launch.frame(), gateway_encoded.as_ref());
    assert_eq!(gateway_launch.binding().version, 2);
    assert_eq!(gateway_launch.binding().kind, BootstrapKind::GatewayHealth);
    assert_eq!(gateway_launch.binding().watchdog_boot_id, BOOT);
    assert_eq!(
        gateway_launch.binding().frame_sha256,
        sha256_hex(gateway_encoded.as_ref())
    );

    let worker_request = make_request(BrokerComponent::Harness, "harness", NONCE);
    let worker_frame = worker(&worker_request, BOOT, "harness");
    let worker_launch = BrokerBootstrapLaunch::for_worker(&worker_request, &worker_frame)
        .expect("worker launch binding should succeed");
    assert_eq!(worker_launch.frame(), worker_frame.frame());
    assert_eq!(worker_launch.binding().version, 2);
    assert_eq!(worker_launch.binding().kind, BootstrapKind::Worker);
    assert_eq!(worker_launch.binding().watchdog_boot_id, BOOT);
    assert_eq!(
        worker_launch.binding().frame_sha256,
        worker_frame.frame_sha256()
    );
    assert_eq!(worker_launch.worker_expected_peer(), Ok(Some(linux_peer())));
}

#[test]
fn binding_role_and_request_nonce_are_closed() {
    let gateway_request = make_request(BrokerComponent::Gateway, "gateway", NONCE);
    let gateway_frame = gateway(&gateway_request);
    let encoded = gateway_frame.encoded_frame();
    let gateway_binding = make_binding(BootstrapKind::GatewayHealth, BOOT, encoded.as_ref());
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &make_request(BrokerComponent::Harness, "harness", NONCE),
            gateway_binding.clone(),
            encoded.as_ref(),
        )
        .is_err()
    );
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &make_request(BrokerComponent::Gateway, "gateway", OTHER_NONCE),
            gateway_binding,
            encoded.as_ref(),
        )
        .is_err()
    );

    let worker_request = make_request(BrokerComponent::Harness, "harness", NONCE);
    let worker_frame = worker(&worker_request, BOOT, "harness");
    let worker_binding = make_binding(BootstrapKind::Worker, BOOT, worker_frame.frame());
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &make_request(BrokerComponent::Gateway, "gateway", NONCE),
            worker_binding.clone(),
            worker_frame.frame(),
        )
        .is_err()
    );
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &make_request(BrokerComponent::Harness, "harness", OTHER_NONCE),
            worker_binding,
            worker_frame.frame(),
        )
        .is_err()
    );
}

#[test]
fn worker_boot_and_component_bindings_are_exact() {
    let request = make_request(BrokerComponent::Harness, "harness", NONCE);
    let frame = worker(&request, BOOT, "harness");

    let mut wrong_boot = make_binding(BootstrapKind::Worker, OTHER_BOOT, frame.frame());
    assert!(
        BrokerBootstrapLaunch::from_frame(&request, wrong_boot.clone(), frame.frame()).is_err()
    );
    wrong_boot.watchdog_boot_id = BOOT.to_owned();

    let wrong_component = worker(&request, BOOT, "other-worker");
    let wrong_component_binding =
        make_binding(BootstrapKind::Worker, BOOT, wrong_component.frame());
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &request,
            wrong_component_binding,
            wrong_component.frame(),
        )
        .is_err()
    );

    assert!(
        BrokerBootstrapLaunch::from_frame(
            &request,
            make_binding(BootstrapKind::Worker, BOOT, frame.frame()),
            frame.frame(),
        )
        .is_ok()
    );
}

#[test]
fn digest_magic_length_and_trailing_bytes_fail_closed() {
    let gateway_request = make_request(BrokerComponent::Gateway, "gateway", NONCE);
    let gateway_frame = gateway(&gateway_request);
    let gateway_encoded = gateway_frame.encoded_frame();

    let mut wrong_digest =
        make_binding(BootstrapKind::GatewayHealth, BOOT, gateway_encoded.as_ref());
    wrong_digest.frame_sha256 = "b".repeat(64);
    assert!(BrokerBootstrapLaunch::from_frame(
        &gateway_request,
        wrong_digest,
        gateway_encoded.as_ref(),
    )
    .is_err());

    let mut wrong_magic = gateway_encoded.to_vec();
    wrong_magic[0] ^= 1;
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &gateway_request,
            make_binding(BootstrapKind::GatewayHealth, BOOT, &wrong_magic),
            &wrong_magic,
        )
        .is_err()
    );
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &gateway_request,
            make_binding(
                BootstrapKind::GatewayHealth,
                BOOT,
                &gateway_encoded[..HEALTH_FRAME_BYTES - 1],
            ),
            &gateway_encoded[..HEALTH_FRAME_BYTES - 1],
        )
        .is_err()
    );
    let mut trailing = gateway_encoded.to_vec();
    trailing.push(0);
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &gateway_request,
            make_binding(BootstrapKind::GatewayHealth, BOOT, &trailing),
            &trailing,
        )
        .is_err()
    );

    let worker_request = make_request(BrokerComponent::Harness, "harness", NONCE);
    let worker_frame = worker(&worker_request, BOOT, "harness");
    let mut worker_magic = worker_frame.frame().to_vec();
    worker_magic[0] ^= 1;
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &worker_request,
            make_binding(BootstrapKind::Worker, BOOT, &worker_magic),
            &worker_magic,
        )
        .is_err()
    );
    let mut worker_trailing = worker_frame.frame().to_vec();
    worker_trailing.push(0);
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &worker_request,
            make_binding(BootstrapKind::Worker, BOOT, &worker_trailing),
            &worker_trailing,
        )
        .is_err()
    );
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &worker_request,
            make_binding(
                BootstrapKind::Worker,
                BOOT,
                &worker_frame.frame()[..worker_frame.frame().len() - 1],
            ),
            &worker_frame.frame()[..worker_frame.frame().len() - 1],
        )
        .is_err()
    );
}

#[test]
fn worker_requires_linux_expected_peer() {
    let request = make_request(BrokerComponent::Harness, "harness", NONCE);
    let windows_peer = WindowsPeer::new(
        17,
        "123",
        r"C:\harness.exe",
        "a".repeat(64),
        1,
        "S-1-5-21-1",
    )
    .expect("test Windows peer is valid");
    let worker = WorkerBootstrap::windows(uuid(NONCE), uuid(BOOT), "harness", windows_peer)
        .expect("test Windows worker bootstrap is valid");
    let frame = encode_frame(&worker).expect("test Windows frame is encodable");
    assert!(
        BrokerBootstrapLaunch::from_frame(
            &request,
            make_binding(BootstrapKind::Worker, BOOT, &frame),
            &frame,
        )
        .is_err()
    );
}

#[test]
fn binding_serde_is_closed_and_launch_debug_is_redacted() {
    let request = make_request(BrokerComponent::Gateway, "gateway", NONCE);
    let gateway_frame = gateway(&request);
    let encoded = gateway_frame.encoded_frame();
    let binding = make_binding(BootstrapKind::GatewayHealth, BOOT, encoded.as_ref());
    let serialized = serde_json::to_string(&binding).expect("binding is serializable");
    assert!(serialized.contains("gateway_health"));
    assert!(!serialized.contains("STS2GH01"));
    assert!(!serialized.contains("a5a5a5a5"));

    let unknown = json!({
        "version": 2,
        "kind": "gateway_health",
        "watchdog_boot_id": BOOT,
        "frame_sha256": "a".repeat(64),
        "unexpected": true,
    });
    assert!(serde_json::from_value::<BrokerBootstrapBinding>(unknown).is_err());
    let duplicate = format!(
        r#"{{"version":2,"kind":"gateway_health","watchdog_boot_id":"{BOOT}","frame_sha256":"{}","version":2}}"#,
        "a".repeat(64)
    );
    assert!(serde_json::from_str::<BrokerBootstrapBinding>(&duplicate).is_err());

    let launch = BrokerBootstrapLaunch::for_gateway(&request, BOOT, &gateway_frame)
        .expect("Gateway launch binding should succeed");
    let debug = format!("{launch:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("STS2GH01"));
    assert!(!debug.contains("a5a5a5a5"));

    let malformed = b"ASC-WB01 secret-key-text";
    let error = BrokerBootstrapLaunch::from_frame(
        &make_request(BrokerComponent::Harness, "harness", NONCE),
        make_binding(BootstrapKind::Worker, BOOT, malformed),
        malformed,
    )
    .expect_err("malformed worker frame must fail");
    let message = error.to_string();
    assert!(!message.contains("secret-key-text"));
    assert!(!message.contains("ASC-WB01"));
}

#[test]
fn launch_state_is_immutable_and_rechecks_without_admission_authority() {
    let request = make_request(BrokerComponent::Harness, "harness", NONCE);
    let worker = worker(&request, BOOT, "harness");
    let original_frame = worker.frame().to_vec();
    let mut supplied_binding = make_binding(BootstrapKind::Worker, BOOT, &original_frame);
    let launch =
        BrokerBootstrapLaunch::from_frame(&request, supplied_binding.clone(), &original_frame)
            .expect("worker launch binding should succeed");

    supplied_binding.frame_sha256 = "c".repeat(64);
    let mut mutated_input = original_frame.clone();
    mutated_input[0] ^= 1;
    assert_eq!(launch.frame(), original_frame.as_slice());
    assert_eq!(launch.binding().frame_sha256, sha256_hex(&original_frame));
    assert!(launch.validate_for_request(&request).is_ok());
    assert!(
        launch
            .validate_for_request(&make_request(
                BrokerComponent::Harness,
                "harness",
                OTHER_NONCE
            ))
            .is_err()
    );
    assert_eq!(mutated_input[0], original_frame[0] ^ 1);
}

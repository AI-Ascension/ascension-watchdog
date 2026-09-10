use super::*;
use crate::platform::gateway_health::GatewayHealthBootstrap;
use crate::platform::linux_broker::tests::{FakeBackend, transport_policy};
use crate::platform::linux_broker::{BrokerComponent, BrokerLifecycleState, BrokerPolicy};
use std::collections::BTreeMap;
use std::io::Write;
use std::time::Duration;
use uuid::Uuid;

fn fixture() -> Result<(BrokerRequest, BrokerBootstrapLaunch), Box<dyn std::error::Error>> {
    let request = BrokerRequest {
        component: BrokerComponent::Gateway,
        instance: "gateway".to_owned(),
        incarnation: "runtime-1".to_owned(),
        nonce: "00000000-0000-4000-8000-000000000011".to_owned(),
    };
    let health = GatewayHealthBootstrap::new(Uuid::parse_str(&request.nonce)?, [0x7b; 32])?;
    let bootstrap = BrokerBootstrapLaunch::for_gateway(
        &request,
        "00000000-0000-4000-8000-000000000022",
        &health,
    )?;
    Ok((request, bootstrap))
}

fn gateway_policy() -> BrokerPolicy {
    let base = transport_policy();
    let launch = base.components[&BrokerComponent::Synthetic].clone();
    // `transport_policy` intentionally uses the current test process through
    // `/proc/self/exe`; production policy construction still rejects procfs
    // paths.  Keep this test-only fixture outside that production validator.
    BrokerPolicy {
        peer: base.peer,
        components: BTreeMap::from([(BrokerComponent::Gateway, launch)]),
    }
}

fn credentials(policy: &BrokerPolicy) -> PeerCredentials {
    PeerCredentials {
        pid: std::process::id(),
        uid: policy.peer.uid,
        gid: policy.peer.gid,
    }
}

#[test]
fn binary_frame_is_not_json_and_header_contains_only_binding()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let bytes = encode_request(&request, &bootstrap)?;
    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_err());
    let header_length = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
    let header: serde_json::Value =
        serde_json::from_slice(&bytes[PREFIX_BYTES..PREFIX_BYTES + header_length])?;
    assert_eq!(header.as_object().expect("header object").len(), 3);
    assert!(header.get("frame").is_none());
    assert!(header.get("key").is_none());
    assert!(
        !bytes[PREFIX_BYTES..PREFIX_BYTES + header_length]
            .windows(32)
            .any(|part| part == [0x7b; 32])
    );
    let (decoded_request, decoded) = decode_request(&bytes)?;
    assert_eq!(decoded_request, request);
    assert_eq!(decoded.binding(), bootstrap.binding());
    assert_eq!(decoded.frame(), bootstrap.frame());
    Ok(())
}

#[test]
fn binary_transport_rejects_truncation_trailing_bytes_lengths_and_changed_frame()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let bytes = encode_request(&request, &bootstrap)?;
    for length in [0, 7, 8, 12, PREFIX_BYTES, bytes.len() - 1] {
        assert!(decode_request(&bytes[..length]).is_err());
    }
    let mut changed = bytes.to_vec();
    changed.push(0);
    assert!(decode_request(&changed).is_err());
    for range in [8..12, 12..16] {
        let mut changed = bytes.to_vec();
        changed[range].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_request(&changed).is_err());
    }
    let mut changed = bytes.to_vec();
    *changed.last_mut().expect("nonempty frame") ^= 1;
    assert!(decode_request(&changed).is_err());
    Ok(())
}

#[test]
fn binary_envelope_rejects_unknown_duplicate_and_secret_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let bytes = encode_request(&request, &bootstrap)?;
    let header_length = u32::from_be_bytes(bytes[8..12].try_into()?) as usize;
    let original = std::str::from_utf8(&bytes[PREFIX_BYTES..PREFIX_BYTES + header_length])?;
    for extra in [
        r#""key":"must-not-be-reflected","#,
        r#""version":2,"#,
        r#""command":"/bin/sh","#,
    ] {
        let header = format!("{{{extra}{}", &original[1..]);
        let mut changed = bytes[..PREFIX_BYTES].to_vec();
        changed[8..12].copy_from_slice(&u32::try_from(header.len())?.to_be_bytes());
        changed.extend_from_slice(header.as_bytes());
        changed.extend_from_slice(bootstrap.frame());
        let error = decode_request(&changed).expect_err("closed envelope rejects extra");
        assert!(!error.to_string().contains("must-not-be-reflected"));
        assert!(!error.to_string().contains("/bin/sh"));
    }
    Ok(())
}

#[test]
fn fixed_policy_nonce_is_rejected_and_generated_nonce_is_not_a_key()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let mut policy = gateway_policy().components[&BrokerComponent::Gateway].clone();
    let environment = launch_environment(&policy, &request, Some(&bootstrap))?;
    assert_eq!(
        environment,
        vec![format!("{HEALTH_NONCE_ENV}={}", request.nonce)]
    );
    policy
        .environment
        .push((HEALTH_NONCE_ENV.to_owned(), request.nonce.clone()));
    assert!(launch_environment(&policy, &request, Some(&bootstrap)).is_err());
    assert!(launch_environment(&policy, &request, None).is_ok());
    policy.environment = (0..super::super::MAX_ENVIRONMENT)
        .map(|index| (format!("KEY_{index}"), "value".to_owned()))
        .collect();
    assert!(launch_environment(&policy, &request, Some(&bootstrap)).is_err());
    policy.environment.pop();
    assert_eq!(
        launch_environment(&policy, &request, Some(&bootstrap))?.len(),
        super::super::MAX_ENVIRONMENT
    );
    Ok(())
}

#[test]
fn authenticated_unix_binary_launch_delivers_exact_frame_once()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let policy = gateway_policy();
    let credentials = credentials(&policy);
    let broker = LinuxSystemdBroker::new(policy, FakeBackend::new());
    let (mut client, mut server) = UnixStream::pair()?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let bytes = encode_request(&request, &bootstrap)?;
    let handle = std::thread::spawn(move || {
        let mut broker = broker;
        let result = super::super::handle_connection(&mut server, &mut broker, deadline);
        (result, broker)
    });
    client.write_all(&bytes)?;
    client.shutdown(std::net::Shutdown::Write)?;
    let response = read_frame(&mut client, deadline)?;
    let (result, mut broker) = handle.join().expect("broker fixture thread");
    result?;
    let receipt = decode_response(&response, &request, bootstrap.binding())?;
    assert_eq!(broker.backend.starts, 1);
    assert_eq!(broker.backend.bootstraps.len(), 1);
    assert_eq!(broker.backend.bootstraps[0].0, *bootstrap.binding());
    assert_eq!(broker.backend.bootstraps[0].1, bootstrap.frame());
    let duplicate = broker.handle_with_bootstrap(credentials, &request, &bootstrap)?;
    assert!(duplicate.duplicate);
    assert_eq!(duplicate.pid, receipt.pid);
    assert_eq!(broker.backend.starts, 1);
    assert!(broker.handle(credentials, request.clone()).is_err());
    assert_eq!(broker.backend.starts, 1);
    Ok(())
}

#[test]
fn lost_binary_response_retains_receipt_for_inspect_and_exact_stop()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let policy = gateway_policy();
    let credentials = credentials(&policy);
    let mut broker = LinuxSystemdBroker::new(policy, FakeBackend::new());
    let (mut client, mut server) = UnixStream::pair()?;
    client.write_all(&encode_request(&request, &bootstrap)?)?;
    client.shutdown(std::net::Shutdown::Write)?;
    drop(client);
    assert!(
        super::super::handle_connection(
            &mut server,
            &mut broker,
            Instant::now() + Duration::from_secs(30)
        )
        .is_err()
    );
    assert_eq!(broker.backend.starts, 1);
    assert_eq!(
        broker.inspect(credentials, request.clone())?.state,
        BrokerLifecycleState::Active
    );
    assert_eq!(
        broker.stop(credentials, request.clone())?.state,
        BrokerLifecycleState::Stopped
    );
    assert!(
        broker
            .handle_with_bootstrap(credentials, &request, &bootstrap)
            .is_err()
    );
    assert_eq!(broker.backend.starts, 1);
    Ok(())
}

#[test]
fn invalid_binary_frame_never_reserves_or_calls_backend() -> Result<(), Box<dyn std::error::Error>>
{
    let (request, bootstrap) = fixture()?;
    let policy = gateway_policy();
    let mut broker = LinuxSystemdBroker::new(policy, FakeBackend::new());
    let mut bytes = encode_request(&request, &bootstrap)?;
    *bytes.last_mut().expect("frame exists") ^= 1;
    let (mut client, mut server) = UnixStream::pair()?;
    client.write_all(&bytes)?;
    client.shutdown(std::net::Shutdown::Write)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    super::super::handle_connection(&mut server, &mut broker, deadline)?;
    server.shutdown(std::net::Shutdown::Write)?;
    let response = read_frame(&mut client, deadline)?;
    assert!(decode_response(&response, &request, bootstrap.binding()).is_err());
    assert!(!broker.ledger.contains(&request));
    assert_eq!(broker.backend.starts, 0);
    Ok(())
}

fn worker_fixture(
    peer: crate::worker_bootstrap::LinuxPeer,
) -> Result<(BrokerRequest, BrokerBootstrapLaunch), Box<dyn std::error::Error>> {
    let request = BrokerRequest {
        component: BrokerComponent::Harness,
        instance: "harness".to_owned(),
        incarnation: "runtime-1".to_owned(),
        nonce: "00000000-0000-4000-8000-000000000044".to_owned(),
    };
    let worker = crate::worker_bootstrap::WorkerBootstrap::linux(
        Uuid::parse_str(&request.nonce)?,
        Uuid::parse_str("00000000-0000-4000-8000-000000000022")?,
        request.instance.clone(),
        peer,
    )?;
    let launch = crate::worker_bootstrap::WorkerBootstrapLaunch::new(worker)?;
    let bootstrap = BrokerBootstrapLaunch::for_worker(&request, &launch)?;
    Ok((request, bootstrap))
}

#[test]
fn worker_controller_binding_accepts_decimal_ticks_and_rejects_each_changed_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let policy = gateway_policy();
    let credentials = credentials(&policy);
    let birth = process_start_token(credentials.pid)?;
    let (_, ticks) = birth.rsplit_once(':').expect("boot-scoped broker birth");
    let peer = crate::worker_bootstrap::LinuxPeer::new(
        credentials.pid,
        ticks,
        policy
            .peer
            .executable
            .to_str()
            .expect("test executable UTF-8"),
        policy.peer.executable_sha256.clone(),
        credentials.uid,
        credentials.gid,
    )?;
    let (_, valid) = worker_fixture(peer.clone())?;
    let deadline = Instant::now() + Duration::from_secs(30);
    authenticate_worker_peer(&valid, credentials, &policy.peer, deadline)?;
    for index in 0..6 {
        let mut changed = peer.clone();
        match index {
            0 => changed.pid = credentials.pid + 1,
            1 => changed.uid = credentials.uid + 1,
            2 => changed.gid = credentials.gid + 1,
            3 => changed.creation_token = format!("{}", ticks.parse::<u64>()? + 1),
            4 => changed.executable = "/usr/bin/unapproved-worker-controller".to_owned(),
            _ => changed.executable_sha256 = "0".repeat(64),
        }
        let (_, invalid) = worker_fixture(changed)?;
        assert!(authenticate_worker_peer(&invalid, credentials, &policy.peer, deadline).is_err());
    }
    Ok(())
}

#[test]
fn typed_worker_admission_preserves_controller_and_exact_frame()
-> Result<(), Box<dyn std::error::Error>> {
    let base = gateway_policy();
    let launch = base.components[&BrokerComponent::Gateway].clone();
    let policy = BrokerPolicy {
        peer: base.peer,
        components: BTreeMap::from([(BrokerComponent::Harness, launch)]),
    };
    let credentials = credentials(&policy);
    let birth = process_start_token(credentials.pid)?;
    let (_, ticks) = birth.rsplit_once(':').expect("boot-scoped broker birth");
    let peer = crate::worker_bootstrap::LinuxPeer::new(
        credentials.pid,
        ticks,
        policy
            .peer
            .executable
            .to_str()
            .expect("test executable UTF-8"),
        policy.peer.executable_sha256.clone(),
        credentials.uid,
        credentials.gid,
    )?;
    let (request, bootstrap) = worker_fixture(peer)?;
    let mut broker = LinuxSystemdBroker::new(policy, FakeBackend::new());
    let receipt = broker.handle_with_bootstrap(credentials, &request, &bootstrap)?;
    assert_eq!(receipt.request, request);
    assert_eq!(broker.backend.starts, 1);
    assert_eq!(broker.backend.bootstraps[0].1, bootstrap.frame());
    Ok(())
}

#[test]
fn typed_response_rejects_changed_binding_and_unknown_receipt_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let policy = gateway_policy();
    let launch = &policy.components[&BrokerComponent::Gateway];
    let receipt = LaunchReceipt {
        request: request.clone(),
        unit: unit_name(&request),
        pid: 42,
        creation_token: "test-birth".to_owned(),
        executable: launch.executable.clone(),
        executable_sha256: launch.executable_sha256.clone(),
        uid: launch.target_uid,
        gid: launch.target_gid,
        capability_bounding_set: 0,
        ambient_capabilities: 0,
        control_group: format!("/system.slice/{}", unit_name(&request)),
        duplicate: false,
    };
    let response = Response {
        version: VERSION,
        accepted: true,
        duplicate: false,
        binding: Some(bootstrap.binding().clone()),
        receipt: Some(receipt),
    };
    let bytes = serde_json::to_vec(&response)?;
    assert!(decode_response(&bytes, &request, bootstrap.binding()).is_ok());
    let original: serde_json::Value = serde_json::from_slice(&bytes)?;
    for index in 0..5 {
        let mut changed = original.clone();
        match index {
            0 => changed["binding"]["frame_sha256"] = serde_json::json!("b".repeat(64)),
            1 => {
                changed["binding"]["watchdog_boot_id"] =
                    serde_json::json!("00000000-0000-4000-8000-000000000033")
            }
            2 => changed["receipt"]["pid"] = serde_json::json!(0),
            3 => changed["receipt"]["unexpected"] = serde_json::json!(true),
            _ => changed["duplicate"] = serde_json::json!(true),
        }
        assert!(
            decode_response(
                &serde_json::to_vec(&changed)?,
                &request,
                bootstrap.binding()
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn preflight_failure_is_not_dispatched_but_preserves_prior_identity_uncertainty()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut request, bootstrap) = fixture()?;
    request.nonce = "00000000-0000-4000-8000-000000000055".to_owned();
    let client = BrokerClient {
        socket: "/no-broker-socket-is-opened-by-this-test".into(),
        timeout: Duration::from_secs(1),
    };
    assert!(matches!(
        client.launch_with_bootstrap(&request, &bootstrap),
        Err(BrokerBootstrapLaunchError::NotDispatched(_))
    ));
    Ok(())
}

#[test]
fn negative_or_lost_reply_after_dispatch_is_explicitly_unknown()
-> Result<(), Box<dyn std::error::Error>> {
    let (request, bootstrap) = fixture()?;
    let bytes = encode_request(&request, &bootstrap)?;
    for reject in [false, true] {
        let (mut client, mut server) = UnixStream::pair()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        let handle = std::thread::spawn(move || -> BrokerResult<()> {
            let _received = read_request(&mut server, deadline)?;
            if reject {
                let response = Response {
                    version: VERSION,
                    accepted: false,
                    duplicate: false,
                    binding: None,
                    receipt: None,
                };
                let bytes =
                    serde_json::to_vec(&response).map_err(|_| invalid("fixture response"))?;
                write_deadline(&mut server, &bytes, deadline)?;
            }
            Ok(())
        });
        let result = dispatch(&mut client, &bytes, &request, bootstrap.binding(), deadline);
        handle.join().expect("bounded reply fixture")?;
        assert!(matches!(
            result,
            Err(BrokerBootstrapLaunchError::Unknown(_))
        ));
    }
    Ok(())
}

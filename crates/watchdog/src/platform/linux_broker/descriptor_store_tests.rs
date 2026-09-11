use super::*;
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
use std::io::IoSliceMut;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

fn receive(socket: &UnixDatagram) -> Result<(String, Vec<File>), Box<dyn std::error::Error>> {
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = [0_u8; 512];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    assert!(
        !message
            .flags
            .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
    );
    let mut descriptors = Vec::new();
    for item in ancillary.drain() {
        if let RecvAncillaryMessage::ScmRights(rights) = item {
            descriptors.extend(rights.map(File::from));
        }
    }
    Ok((
        String::from_utf8(bytes[..message.bytes].to_vec())?,
        descriptors,
    ))
}

fn name() -> DescriptorName {
    DescriptorName::parse(&format!("cg-{}", "a".repeat(64))).expect("bounded name")
}

#[test]
fn real_descriptor_transfer_and_separate_barrier_preserve_original_directory()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let file = File::open(directory.path())?;
    let expected = file.metadata()?;
    let (client, manager) = UnixDatagram::pair()?;
    let transport = DescriptorStoreTransport::from_connected(client)?;
    let server = std::thread::spawn(move || {
        let (message, descriptors) = receive(&manager).expect("receive stored descriptor");
        assert_eq!(
            message,
            format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}\n", name().as_str())
        );
        assert_eq!(descriptors.len(), 1);
        assert!(
            descriptors[0]
                .metadata()
                .expect("directory metadata")
                .is_dir()
        );
        let (barrier, writers) = receive(&manager).expect("separate barrier");
        assert_eq!(barrier, "BARRIER=1\n");
        assert_eq!(writers.len(), 1);
        drop(writers);
        descriptors
    });
    let _processed = transport.submit(&name(), &file, Instant::now() + Duration::from_secs(2))?;
    drop(file);
    let stored = server.join().map_err(|_| "manager fixture failed")?;
    let actual = stored[0].metadata()?;
    assert_eq!(
        (actual.dev(), actual.ino()),
        (expected.dev(), expected.ino())
    );
    Ok(())
}

#[test]
fn removal_is_exact_named_and_barrier_has_the_only_descriptor()
-> Result<(), Box<dyn std::error::Error>> {
    let (client, manager) = UnixDatagram::pair()?;
    let transport = DescriptorStoreTransport::from_connected(client)?;
    let server = std::thread::spawn(move || {
        let (message, descriptors) = receive(&manager).expect("remove notification");
        assert_eq!(
            message,
            format!("FDSTOREREMOVE=1\nFDNAME={}\n", name().as_str())
        );
        assert!(descriptors.is_empty());
        let (message, writers) = receive(&manager).expect("remove barrier");
        assert_eq!(message, "BARRIER=1\n");
        assert_eq!(writers.len(), 1);
    });
    let _processed = transport.remove(&name(), Instant::now() + Duration::from_secs(2))?;
    server.join().map_err(|_| "manager fixture failed")?;
    Ok(())
}

#[test]
fn an_ignored_store_can_pass_the_barrier_without_proving_storage()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let file = File::open(directory.path())?;
    let (client, manager) = UnixDatagram::pair()?;
    let transport = DescriptorStoreTransport::from_connected(client)?;
    let server = std::thread::spawn(move || {
        let (_, descriptors) = receive(&manager).expect("ignored store");
        drop(descriptors);
        let (message, barrier) = receive(&manager).expect("processed barrier");
        assert_eq!(message, "BARRIER=1\n");
        drop(barrier);
    });
    let _only_processed =
        transport.submit(&name(), &file, Instant::now() + Duration::from_secs(2))?;
    server.join().map_err(|_| "manager fixture failed")?;
    Ok(())
}

#[test]
fn a_nonresponsive_manager_cannot_extend_the_absolute_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let file = File::open(directory.path())?;
    let (client, _manager) = UnixDatagram::pair()?;
    let transport = DescriptorStoreTransport::from_connected(client)?;
    let start = Instant::now();
    assert!(
        transport
            .submit(&name(), &file, start + Duration::from_millis(30))
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    Ok(())
}

#[test]
fn invalid_names_files_and_expired_admission_have_no_transport_effect()
-> Result<(), Box<dyn std::error::Error>> {
    for invalid in [
        "",
        "stored",
        "cg-ABC",
        "cg-name:alias",
        "cg-name\nFDSTOREREMOVE=1",
    ] {
        assert!(DescriptorName::parse(invalid).is_err());
    }
    let (client, manager) = UnixDatagram::pair()?;
    let transport = DescriptorStoreTransport::from_connected(client)?;
    let file = tempfile::tempfile()?;
    assert!(
        transport
            .submit(&name(), &file, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    assert!(
        transport
            .remove(
                &name(),
                Instant::now()
                    .checked_sub(Duration::from_secs(1))
                    .ok_or("test clock cannot express past deadline")?
            )
            .is_err()
    );
    manager.set_nonblocking(true)?;
    assert_eq!(
        manager
            .recv(&mut [0_u8; 512])
            .expect_err("no datagram")
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    Ok(())
}

#[test]
fn descriptor_name_binds_receipt_identity_but_not_duplicate_transport_flag()
-> Result<(), Box<dyn std::error::Error>> {
    use super::super::{BrokerComponent, BrokerRequest};
    let mut receipt = LaunchReceipt {
        request: BrokerRequest {
            component: BrokerComponent::Synthetic,
            instance: "instance".to_owned(),
            incarnation: "incarnation".to_owned(),
            nonce: "nonce".to_owned(),
        },
        unit: "unit".to_owned(),
        pid: 42,
        creation_token: "boot:11111111-1111-4111-8111-111111111111:42".to_owned(),
        executable: "/approved/fixture".into(),
        executable_sha256: "a".repeat(64),
        uid: 1001,
        gid: 1001,
        capability_bounding_set: 0,
        ambient_capabilities: 0,
        control_group: "/system.slice/unit".to_owned(),
        duplicate: false,
    };
    let first = DescriptorName::for_receipt(&receipt)?;
    receipt.duplicate = true;
    assert_eq!(first, DescriptorName::for_receipt(&receipt)?);
    receipt.pid += 1;
    assert_ne!(first, DescriptorName::for_receipt(&receipt)?);
    receipt.pid -= 1;
    receipt.creation_token.push('1');
    assert_ne!(first, DescriptorName::for_receipt(&receipt)?);
    assert!(DescriptorName::parse(first.as_str()).is_ok());
    Ok(())
}

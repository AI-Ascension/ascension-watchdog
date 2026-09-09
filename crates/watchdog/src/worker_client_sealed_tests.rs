//! Real sealed-image child regression; no service or cgroup changes.
use super::*;
use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "entry point invoked only by the sealed-image parent regression"]
fn sealed_peer_fixture() {
    let socket = std::env::var_os("ASCENSION_SEALED_PEER_TEST_SOCKET").expect("fixture socket");
    let listener = UnixListener::bind(socket).expect("fixture listener");
    let (mut peer, _) = listener.accept().expect("fixture peer");
    peer.set_read_timeout(Some(Duration::from_mins(3)))
        .expect("fixture deadline");
    let mut byte = [0_u8];
    peer.read_exact(&mut byte).expect("fixture completion");
    if byte[0] == 2 {
        use std::os::unix::process::CommandExt;
        let error = Command::new("/bin/sleep").arg("30").exec();
        panic!("fixture image replacement failed: {error}");
    }
}

#[test]
fn sealed_owned_peer_authenticates_and_rejects_wrong_birth_or_image()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::io::{Seek, Write};
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("peer.sock");
    let executable = std::env::current_exe()?;
    let mut image = File::from(memfd_create(
        "ascension-sealed-peer-test",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    std::io::copy(&mut File::open(&executable)?, &mut image)?;
    fcntl_add_seals(
        &image,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )?;
    image.rewind()?;
    let digest = hash_file_until(&mut image, None)?;
    let mut child = ChildGuard(
        Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
            .args([
                "--exact",
                "worker_client::auth::sealed_tests::sealed_peer_fixture",
                "--ignored",
            ])
            .env("ASCENSION_SEALED_PEER_TEST_SOCKET", &socket)
            .stdout(Stdio::null())
            .spawn()?,
    );
    let startup = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match UnixStream::connect(&socket) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < startup => {
                let _ = error;
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    let budget = if cfg!(debug_assertions) { 90 } else { 5 };
    let deadline = Instant::now() + Duration::from_secs(budget);
    let ticks = process_start_token(child.0.id(), deadline)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let mut portable = crate::ProcessIdentity {
        pid: child.0.id(),
        launch_nonce: "sealed-test".to_owned(),
        executable,
        executable_digest: digest,
        started_at_ms: 0,
        creation_fingerprint: Some(format!("{}:{ticks}", boot.trim())),
    };
    let identity = WorkerPeerIdentity::from_owned_linux_process(&portable, deadline)?;
    assert!(WorkerPeerIdentity::from_process_identity(&portable).is_err());
    let session =
        authenticate_linux_peer(&stream, &identity, Instant::now() + Duration::from_secs(1))?;
    session.verify_current(Instant::now() + Duration::from_secs(1))?;
    // Removing the private sealed-image proof restores ordinary strict path
    // authentication; an approved digest alone cannot select memfd policy.
    let mut ordinary = identity.clone();
    ordinary.sealed_image = None;
    assert!(
        authenticate_linux_peer(&stream, &ordinary, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    let mut wrong_image = identity.clone();
    wrong_image.configured_image_identity.inode =
        wrong_image.configured_image_identity.inode.wrapping_add(1);
    assert!(
        authenticate_linux_peer(
            &stream,
            &wrong_image,
            Instant::now() + Duration::from_secs(1)
        )
        .is_err()
    );
    let wrong_account = identity.clone().with_peer_credentials(
        rustix::process::geteuid().as_raw().wrapping_add(1),
        rustix::process::getegid().as_raw(),
    )?;
    assert!(
        authenticate_linux_peer(
            &stream,
            &wrong_account,
            Instant::now() + Duration::from_secs(1),
        )
        .is_err()
    );
    let mut wrong_digest = portable.clone();
    wrong_digest.executable_digest = "0".repeat(64);
    assert!(
        WorkerPeerIdentity::from_owned_linux_process(
            &wrong_digest,
            Instant::now() + Duration::from_secs(budget),
        )
        .is_err()
    );
    portable.creation_fingerprint = Some(format!("wrong-boot:{ticks}"));
    assert!(WorkerPeerIdentity::from_owned_linux_process(&portable, deadline).is_err());
    portable.creation_fingerprint = Some(format!("{}:0", boot.trim()));
    assert!(WorkerPeerIdentity::from_owned_linux_process(&portable, deadline).is_err());
    stream.write_all(&[2])?;
    let replacement_deadline = Instant::now() + Duration::from_secs(10);
    while fs::read_link(format!("/proc/{}/exe", child.0.id()))? == session.expected_path {
        assert!(
            Instant::now() < replacement_deadline,
            "fixture did not replace its image"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        session
            .verify_current(Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    assert!(
        authenticate_linux_peer(&stream, &identity, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    child.0.kill()?;
    child.0.wait()?;
    assert!(
        authenticate_linux_peer(&stream, &identity, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    Ok(())
}

#[test]
fn native_peer_capture_rejects_unsealed_and_incomplete_images()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::process::CommandExt;
    let executable = fs::canonicalize("/bin/sleep")?;
    let mut image = File::from(memfd_create(
        "ascension-incomplete-seals-test",
        MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
    )?);
    std::io::copy(&mut File::open(&executable)?, &mut image)?;
    let child = ChildGuard(
        Command::new(format!("/proc/self/fd/{}", image.as_raw_fd()))
            .arg0("sleep")
            .arg("30")
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    let ticks = process_start_token(child.0.id(), deadline)?;
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let identity = crate::ProcessIdentity {
        pid: child.0.id(),
        launch_nonce: "unsealed-test".to_owned(),
        executable,
        executable_digest: "0".repeat(64),
        started_at_ms: 0,
        creation_fingerprint: Some(format!("{}:{ticks}", boot.trim())),
    };
    for incomplete in [false, true] {
        if incomplete {
            fcntl_add_seals(&image, SealFlags::SHRINK | SealFlags::GROW)?;
        }
        assert!(
            matches!(WorkerPeerIdentity::from_owned_linux_process(&identity, deadline),
            Err(WatchdogError::IdentityMismatch(message)) if message == "native worker image is not immutable")
        );
    }
    Ok(())
}

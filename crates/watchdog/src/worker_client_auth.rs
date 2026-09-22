//! Authentication helpers for the owner-local worker handoff transport.
//!
//! The worker credential is deliberately kept out of protocol frames and
//! durable records.  It is presented only in the transport authentication
//! prelude, after the peer process has been checked by the operating system.
//!
//! The implementation is split into cohesive child modules; this file stays
//! the `worker_client_auth` coordinator so every existing path into the module
//! keeps working:
//!
//! - `models` owns the peer identity model, its construction and validation,
//!   the Linux image identity and sealed-image proofs and the bounded
//!   process-start-token and image-digest helpers.
//! - `credential` owns the credential reference checks, the protected
//!   credential object and the deadline-bounded protected read path.
//! - `peer` owns controller image capture and live peer authentication, plus
//!   the retained `LinuxPeerSession` re-verification.
//!
//! Every resulting module is below the 1,000-line target, so no exception has
//! to be documented.  The cross-module integration tests and the sealed-image
//! fixture stay here and exercise the child modules together.

#[cfg(all(test, target_os = "linux"))]
#[path = "worker_client_sealed_tests.rs"]
mod sealed_tests;

// `worker_client` is itself declared with `#[path]`, so this coordinator must
// name the child files explicitly instead of relying on directory derivation.
#[path = "worker_client_auth/credential.rs"]
mod credential;
#[path = "worker_client_auth/models.rs"]
mod models;
#[path = "worker_client_auth/peer.rs"]
mod peer;

pub(crate) use credential::{read_credential, validate_credential_reference};
pub use models::WorkerPeerIdentity;
#[cfg(target_os = "linux")]
pub(crate) use peer::capture_linux_controller;
#[cfg(target_os = "linux")]
pub(crate) use peer::{LinuxPeerSession, authenticate_linux_peer};

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::credential::read_credential;
    use super::models::{
        LinuxFileIdentity, WorkerPeerIdentity, hash_file_until, linux_file_identity,
        process_start_token,
    };
    use super::peer::{LinuxPeerSession, authenticate_linux_peer};
    use crate::error::WatchdogError;
    use std::fs;
    use std::fs::File;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    fn current_peer_session() -> LinuxPeerSession {
        use rustix::process::{Pid, PidfdFlags, pidfd_open};

        let pid = std::process::id();
        let process = Pid::from_raw(i32::try_from(pid).expect("test PID fits i32"))
            .expect("test PID is nonzero");
        let pidfd = pidfd_open(process, PidfdFlags::empty()).expect("test pidfd");
        let executable = fs::read_link(format!("/proc/{pid}/exe")).expect("test executable");
        let image = File::open(format!("/proc/{pid}/exe")).expect("test image");
        let image_identity = linux_file_identity(&image).expect("test image identity");
        let creation_token = process_start_token(pid, Instant::now() + Duration::from_secs(1))
            .expect("test creation token");
        LinuxPeerSession {
            _pidfd: pidfd,
            _image: image,
            image_identity,
            _image_digest: String::new(),
            expected_path: executable,
            expected_pid: pid,
            expected_uid: rustix::process::geteuid().as_raw(),
            expected_gid: rustix::process::getegid().as_raw(),
            creation_token,
        }
    }

    #[test]
    fn forked_socket_writer_credentials_are_rejected() {
        use rustix::net::UCred;
        use rustix::process::{Gid, Pid, Uid};

        let session = current_peer_session();
        let pid = Pid::from_raw(i32::try_from(session.expected_pid).expect("test PID fits i32"))
            .expect("test PID is nonzero");
        let credentials = UCred {
            pid,
            uid: Uid::from_raw(session.expected_uid),
            gid: Gid::from_raw(session.expected_gid),
        };
        session
            .verify_message_credentials(&credentials)
            .expect("original process credentials");

        let inherited_socket_writer = UCred {
            pid: Pid::from_raw(pid.as_raw_pid().saturating_add(1)).expect("alternate PID"),
            ..credentials
        };
        assert!(matches!(
            session.verify_message_credentials(&inherited_socket_writer),
            Err(WatchdogError::IdentityMismatch(_))
        ));
    }

    #[test]
    fn protected_credential_keeps_authority_after_path_replacement() {
        let directory = tempfile::tempdir().expect("credential directory");
        fs::set_permissions(
            directory.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("credential directory permissions");
        let path = directory.path().join("worker.token");
        fs::write(&path, b"held-secret").expect("credential");
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("credential permissions");
        let protected = read_credential(&path, Instant::now() + Duration::from_secs(1))
            .expect("protected credential");
        fs::remove_file(&path).expect("replace credential path");
        assert_eq!(protected.bytes(), b"held-secret");
    }

    #[test]
    fn image_identity_swap_is_rejected_before_peer_digest_use() {
        let (client, _server) = UnixStream::pair().expect("peer socket");
        let executable = std::env::current_exe().expect("test executable");
        let digest = hash_file_until(
            &mut File::open(&executable).expect("test executable file"),
            None,
        )
        .expect("test executable digest");
        let pid = std::process::id();
        let creation_token = process_start_token(pid, Instant::now() + Duration::from_secs(1))
            .expect("test creation token");
        let mut identity = WorkerPeerIdentity::new(executable, digest, pid, creation_token)
            .expect("peer identity");
        identity.configured_image_identity = LinuxFileIdentity {
            device: identity.configured_image_identity.device.wrapping_add(1),
            inode: identity.configured_image_identity.inode,
        };
        let result =
            authenticate_linux_peer(&client, &identity, Instant::now() + Duration::from_secs(1));
        assert!(matches!(result, Err(WatchdogError::IdentityMismatch(_))));
    }
}

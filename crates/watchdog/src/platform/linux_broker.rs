//! Root-owned Linux launch broker.
//!
//! The normal Linux adapter is intentionally retained as a same-UID delegated
//! cgroup adapter.  This module is the stronger, separately deployed boundary:
//! a small root-owned Unix socket authenticates the watchdog peer and accepts
//! only an opaque component/instance/incarnation/nonce request.  All launch
//! details live in a root-owned immutable policy.  The production backend asks
//! PID 1 over the native D-Bus API to create a transient unit, and acknowledges
//! only after checking the exact unit, process start token, credentials,
//! capabilities and cgroup membership.
//!
//! No request field contains an executable path, argument, environment, user,
//! group or cgroup name.  Those are deliberately unrepresentable at the IPC
//! boundary.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use rustix::fs::{Gid, fchown};
use rustix::io::Errno;
use rustix::net::sockopt::socket_peercred;
use rustix::process::{Pid, PidfdFlags, pidfd_open};

const MAX_FRAME_BYTES: usize = 16 * 1024;
const MAX_IDENTITY_BYTES: usize = 128;
const MAX_ARGUMENTS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 8 * 1024;
const MAX_ENVIRONMENT: usize = 64;
const MAX_ENVIRONMENT_BYTES: usize = 8 * 1024;
const MAX_POLICY_COMPONENTS: usize = 8;
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TASKS: u64 = 4096;
const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_mins(2);
const POLL_INTERVAL: Duration = Duration::from_millis(25);
const MAX_IO_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RECEIPTS: usize = 128;
const MAX_ACTIVE_PROCESSES: usize = 64;
const MAX_LEDGER_REQUESTS: usize = MAX_RECEIPTS;
const MAX_LEDGER_TRANSITIONS: usize = MAX_LEDGER_REQUESTS * 4;
// Each admitted request has room for pending, committed, stop-pending and
// stopped records, including a newline per maximum-sized record. Reopen must
// accept every journal which the bounded transition machine can produce.
const MAX_LEDGER_BYTES: usize = MAX_LEDGER_TRANSITIONS * (MAX_FRAME_BYTES + 1);
const BROKER_UNIT_NAME: &str = "ascension-watchdog-broker.service";
pub const BROKER_PROTOCOL_VERSION: u8 = 1;

pub mod bootstrap;
mod bootstrap_transport;
pub use bootstrap_transport::BrokerBootstrapLaunchError;

fn remaining(deadline: Instant) -> BrokerResult<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| BrokerError::Unavailable("broker operation deadline expired".to_owned()))
}

/// Errors returned by the broker boundary.  Error text intentionally does not
/// echo request-controlled paths or arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BrokerError {
    Invalid(String),
    Unauthorized(String),
    Conflict(String),
    Unavailable(String),
    Io(String),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid broker request: {message}"),
            Self::Unauthorized(message) => {
                write!(formatter, "unauthorized broker request: {message}")
            }
            Self::Conflict(message) => write!(formatter, "broker conflict: {message}"),
            Self::Unavailable(message) => write!(formatter, "broker unavailable: {message}"),
            Self::Io(message) => write!(formatter, "broker I/O error: {message}"),
        }
    }
}

impl std::error::Error for BrokerError {}

pub type BrokerResult<T> = Result<T, BrokerError>;

mod protocol;
pub use protocol::{
    BrokerComponent, BrokerLifecycleOperation, BrokerLifecycleRequest, BrokerLifecycleState,
    BrokerPolicy, BrokerRequest, CapabilityPolicy, CgroupPolicy, LaunchPolicy, PeerPolicy,
};
pub(crate) use protocol::{StrictJsonValue, parse_json, validate_sha256};

mod peer;
pub use peer::{PeerCredentials, peer_credentials};
pub(crate) use peer::{
    authenticate_peer, hash_file, hash_open_file_until, is_protected_owner, read_bounded_file,
    validate_protected_directory, validate_protected_file,
};

mod broker;
pub(crate) use broker::verify_receipt_identity;
pub use broker::{BrokerLifecycleReceipt, LaunchReceipt, LinuxSystemdBroker, UnitObservation};
pub(crate) use broker::{receipt_from, unit_name};

mod transport;
#[cfg(test)]
pub(crate) use transport::handle_connection;
pub use transport::{bind_root_owned_socket, serve};
pub(crate) use transport::{read_frame, write_deadline};

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = std::fmt::Write::write_fmt(&mut output, format_args!("{byte:02x}"));
    }
    output
}

#[allow(clippy::needless_pass_by_value)]
fn io_error(error: io::Error) -> BrokerError {
    BrokerError::Io(error.to_string())
}

#[cfg(target_os = "linux")]
mod ledger;
#[cfg(target_os = "linux")]
pub use ledger::BrokerLedger;
#[cfg(target_os = "linux")]
pub use ledger::JobBinding;
mod client;
pub mod descriptor_store;
pub(crate) use client::connect_with_deadline;
pub use client::{BrokerClient, SystemdBackend};

#[cfg(target_os = "linux")]
mod native;
#[cfg(target_os = "linux")]
pub(crate) use native::process_start_token;
#[cfg(all(target_os = "linux", test))]
pub(crate) use native::require_no_supplementary_groups;
#[cfg(target_os = "linux")]
pub use native::run_native_broker;
#[cfg(all(target_os = "linux", test))]
pub(crate) use native::verify_process_executable;
#[cfg(target_os = "linux")]
pub use native::{
    JobRemovalOutcome, JobRemovedEvent, QueuedJobBackend, QueuedJobCancellation,
    QueuedJobResolution, decode_job_removed,
};

#[cfg(test)]
mod tests;

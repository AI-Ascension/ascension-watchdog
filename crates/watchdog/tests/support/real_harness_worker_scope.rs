// SPDX-License-Identifier: MIT

//! OS-backed ownership for the opt-in real-harness daemon.
//!
//! The test process keeps a `Child` handle and a pidfd, while systemd owns an
//! individually named transient scope containing the daemon and its future
//! descendants.  The scope is deliberately verified from systemd's live
//! properties and cgroup-v2 state; an environment variable or a local name
//! registry is not accepted as an ownership proof.
//!
//! The original single-file support module is split along its cohesive seams:
//! pure systemd property/proof parsing (`properties`), canonical file identity
//! and digests (`paths`), bounded helper execution and launcher children
//! (`commands`), retained cgroup-v2 handles (`cgroup`), the durable proof
//! writer (`evidence`) and scope admission/durable stop ownership (`owner`).
//! The shared bound constants stay here; every value the rest of the test crate
//! consumes is re-exported below, so the entrypoint and its `mod tests` child
//! are unchanged.  The children are named with explicit `#[path]` attributes
//! because this file is itself included through a `#[path]` module
//! declaration, which makes nested-module lookup relative to this file's
//! directory.

use std::time::Duration;

const SYSTEMD_RUN: &str = "/usr/bin/systemd-run";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const ENV: &str = "/usr/bin/env";
const CGROUP_MOUNT: &str = "/sys/fs/cgroup";
const MAX_RUNTIME: Duration = Duration::from_mins(2);
const MAX_STOP: Duration = Duration::from_secs(5);
const START_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(12);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(8);
const POLL_INTERVAL: Duration = Duration::from_millis(10);
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(test)]
#[path = "real_harness_worker_scope_tests.rs"]
mod tests;

#[path = "real_harness_worker_scope/cgroup.rs"]
mod cgroup;
#[path = "real_harness_worker_scope/commands.rs"]
mod commands;
#[path = "real_harness_worker_scope/evidence.rs"]
mod evidence;
#[path = "real_harness_worker_scope/owner.rs"]
mod owner;
#[path = "real_harness_worker_scope/paths.rs"]
mod paths;
#[path = "real_harness_worker_scope/properties.rs"]
mod properties;

// This support module is compiled into two different test binaries
// (`real_harness_worker` and `real_harness_worker_scope`), each of which
// consumes a different subset of the re-exported surface, so any single
// build legitimately leaves part of it unused.
#[allow(unused_imports)]
pub(crate) use cgroup::{open_cgroup_directory, open_cgroup_events};
#[allow(unused_imports)]
pub(crate) use commands::{join_command_output, run_bounded};
#[allow(unused_imports)]
pub(crate) use owner::{ScopeLaunch, ScopeOwner};
#[allow(unused_imports)]
pub(crate) use properties::{
    ScopeProof, parse_properties, validate_scope_proof, validate_scope_properties,
    validate_stopped_scope_identity,
};

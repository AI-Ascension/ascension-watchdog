//! Restricted direct process adapter.
//!
//! Only an exact, preconfigured executable is launched.  Cleanup uses the
//! owned `Child` handle plus a creation fingerprint and canonical executable
//! path; Unix synthetic children additionally get an exact process group for
//! descendant cleanup. A PID or executable name by itself is never sufficient.
//!
//! The implementation is split into cohesive child modules; this file stays
//! the `process` coordinator so every existing path into the module keeps
//! working:
//!
//! - `validation` owns the fail-closed pre-spawn validation of one approved
//!   component specification.
//! - `spawn_error` owns the spawn-failure classification, including the
//!   retained `CleanupUncertain` outcome.
//! - `identity` owns the launch identity, its validation, and the executable
//!   digest and creation-fingerprint helpers.
//! - `observation` owns non-reaping child observation, the exact group signal
//!   and the bounded process-group membership proof.
//! - `output` owns bounded diagnostic output capture.
//! - `child` owns [`OwnedChild`] and its process-group authority, the spawn
//!   path, and the stop/reap/`Drop` cleanup paths.
//!
//! Every resulting module is below the 1,000-line target, so no exception has
//! to be documented.  The functional acceptance tests stay at `process::tests`
//! (in `process/tests.rs`) so test discovery and test names are unchanged.

mod child;
mod identity;
mod observation;
mod output;
mod spawn_error;
mod validation;

pub use child::OwnedChild;
pub use identity::{ProcessIdentity, ensure_identity};
pub use output::OutputSnapshot;
pub use spawn_error::ProcessSpawnError;

#[cfg(all(test, unix))]
mod tests;

use std::path::Path;

#[allow(dead_code)]
fn _path_for_docs(path: &Path) -> &Path {
    path
}

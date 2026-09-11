//! Immutable encoded worker bootstrap material for one process launch.

use super::{BootstrapError, WorkerBootstrap, encode_frame};
use crate::config::hex_digest;

/// A validated worker bootstrap together with the exact bytes and digest that
/// the native launcher must deliver to the child.  Keeping these values in one
/// immutable object prevents a later re-encoding or mutable payload from
/// diverging from the durable binding made by the runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerBootstrapLaunch {
    bootstrap: WorkerBootstrap,
    frame: Vec<u8>,
    frame_sha256: String,
}

impl WorkerBootstrapLaunch {
    /// Encode and hash one validated bootstrap exactly once.
    pub fn new(bootstrap: WorkerBootstrap) -> Result<Self, BootstrapError> {
        let frame = encode_frame(&bootstrap)?;
        let frame_sha256 = hex_digest(&frame);
        Ok(Self {
            bootstrap,
            frame,
            frame_sha256,
        })
    }

    /// Return the validated typed bootstrap policy.
    #[must_use]
    pub fn bootstrap(&self) -> &WorkerBootstrap {
        &self.bootstrap
    }

    /// Return the exact encoded bytes to write to the child worker pipe.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Return the lowercase SHA-256 digest of [`Self::frame`].
    #[must_use]
    pub fn frame_sha256(&self) -> &str {
        &self.frame_sha256
    }
}

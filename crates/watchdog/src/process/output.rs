//! Bounded diagnostic output capture for the restricted process adapter.
//!
//! Captured bytes are bounded and are never used as a health or settlement
//! witness; the reader threads only retain a fixed prefix per stream.

use serde::Serialize;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Bounded captured child output.  Output is diagnostic only and never used as
/// a health or settlement witness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutputSnapshot {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub(super) struct BoundedOutput {
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) stdout_truncated: bool,
    pub(super) stderr_truncated: bool,
}

pub(super) fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    output: Arc<Mutex<BoundedOutput>>,
    stdout: bool,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 4 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if let Ok(mut output) = output.lock() {
                        if stdout {
                            let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.stdout.len());
                            if read > remaining {
                                output.stdout.extend_from_slice(&buffer[..remaining]);
                                output.stdout_truncated = true;
                            } else {
                                output.stdout.extend_from_slice(&buffer[..read]);
                            }
                        } else {
                            let remaining = MAX_OUTPUT_BYTES.saturating_sub(output.stderr.len());
                            if read > remaining {
                                output.stderr.extend_from_slice(&buffer[..remaining]);
                                output.stderr_truncated = true;
                            } else {
                                output.stderr.extend_from_slice(&buffer[..read]);
                            }
                        }
                    }
                }
            }
        }
    })
}

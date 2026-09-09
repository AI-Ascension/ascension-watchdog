//! Immutable worker-startup bytes accepted by the native Windows boundary.
//!
//! The watchdog owns the worker-bootstrap codec and schema.  This small
//! transport value deliberately does not decode the payload; it only verifies
//! the fixed wire envelope and keeps one exact byte sequence alive until the
//! native launcher has handed it to the child.  Keeping the bytes behind a
//! private boxed slice prevents a caller from mutating a frame after the
//! launch request has been admitted.

use crate::contract::PlatformError;

/// The fixed worker-bootstrap frame preamble.
const WORKER_BOOTSTRAP_MAGIC: &[u8; 8] = b"ASC-WB01";
/// Maximum UTF-8 payload accepted by worker-bootstrap v1.
const WORKER_BOOTSTRAP_MAX_PAYLOAD: usize = 16_384;
/// Number of bytes occupied by the magic and big-endian payload length.
const WORKER_BOOTSTRAP_PREFIX_BYTES: usize = WORKER_BOOTSTRAP_MAGIC.len() + 4;

/// Maximum complete worker-bootstrap frame accepted by this transport.
pub const MAX_WORKER_BOOTSTRAP_FRAME_BYTES: usize =
    WORKER_BOOTSTRAP_PREFIX_BYTES + WORKER_BOOTSTRAP_MAX_PAYLOAD;

/// One validated, immutable worker-bootstrap frame for a single process
/// launch.
#[derive(Clone, Eq, PartialEq)]
pub struct WorkerBootstrapLaunch {
    frame: Box<[u8]>,
}

impl std::fmt::Debug for WorkerBootstrapLaunch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerBootstrapLaunch")
            .field("frame_bytes", &self.frame.len())
            .finish()
    }
}

impl WorkerBootstrapLaunch {
    /// Admit one complete worker-bootstrap frame without decoding its payload.
    ///
    /// The watchdog codec remains the owner of JSON/schema validation.  The
    /// native boundary nevertheless verifies the immutable wire envelope so a
    /// truncated, over-sized, or unrelated byte stream cannot reach a child.
    pub fn new(frame: Vec<u8>) -> Result<Self, PlatformError> {
        validate_frame(&frame)?;
        Ok(Self {
            frame: frame.into_boxed_slice(),
        })
    }

    /// Return the exact bytes that the native launcher writes to worker stdin.
    #[must_use]
    pub fn frame(&self) -> &[u8] {
        &self.frame
    }

    /// Validate the fixed envelope of this already-owned frame.
    pub fn validate(&self) -> Result<(), PlatformError> {
        validate_frame(&self.frame)
    }
}

fn validate_frame(frame: &[u8]) -> Result<(), PlatformError> {
    if frame.len() < WORKER_BOOTSTRAP_PREFIX_BYTES || frame.len() > MAX_WORKER_BOOTSTRAP_FRAME_BYTES
    {
        return Err(PlatformError::Invalid(
            "worker bootstrap frame is outside its fixed byte bound".to_owned(),
        ));
    }
    if frame.get(..WORKER_BOOTSTRAP_MAGIC.len()) != Some(WORKER_BOOTSTRAP_MAGIC) {
        return Err(PlatformError::Invalid(
            "worker bootstrap frame has an invalid magic".to_owned(),
        ));
    }
    let length_offset = WORKER_BOOTSTRAP_MAGIC.len();
    let declared = u32::from_be_bytes([
        frame[length_offset],
        frame[length_offset + 1],
        frame[length_offset + 2],
        frame[length_offset + 3],
    ]);
    let declared = usize::try_from(declared).map_err(|_| {
        PlatformError::Invalid("worker bootstrap payload length overflows usize".to_owned())
    })?;
    if declared == 0 || declared > WORKER_BOOTSTRAP_MAX_PAYLOAD {
        return Err(PlatformError::Invalid(
            "worker bootstrap payload length is outside bounds".to_owned(),
        ));
    }
    let expected = WORKER_BOOTSTRAP_PREFIX_BYTES
        .checked_add(declared)
        .ok_or_else(|| {
            PlatformError::Invalid("worker bootstrap frame length overflow".to_owned())
        })?;
    if expected != frame.len() {
        return Err(PlatformError::Invalid(
            "worker bootstrap frame length does not match its payload".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = WORKER_BOOTSTRAP_MAGIC.to_vec();
        bytes.extend_from_slice(&(u32::try_from(payload.len()).unwrap()).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn retains_exact_frame_bytes() {
        let bytes = frame(br#"{"version":1}"#);
        let launch = WorkerBootstrapLaunch::new(bytes.clone()).unwrap();
        assert_eq!(launch.frame(), bytes.as_slice());
    }

    #[test]
    fn rejects_bad_envelope_lengths_and_magic() {
        assert!(WorkerBootstrapLaunch::new(Vec::new()).is_err());
        assert!(WorkerBootstrapLaunch::new(b"NOT-WB01\0\0\0\x01x".to_vec()).is_err());
        assert!(WorkerBootstrapLaunch::new(frame(&[])).is_err());
        let mut truncated = frame(b"x");
        truncated.pop();
        assert!(WorkerBootstrapLaunch::new(truncated).is_err());
        assert!(
            WorkerBootstrapLaunch::new(frame(&vec![b'x'; WORKER_BOOTSTRAP_MAX_PAYLOAD + 1]))
                .is_err()
        );
    }
}

//! Secret-bearing storage for bounded protected-file reads.
//!
//! The reader owns one preallocated, zeroizing heap buffer and one zeroizing
//! staging buffer for the lifetime of a read.  The public platform helper may
//! transfer the completed `Vec` to a caller, but it must not copy the bytes
//! while doing so; callers that retain the returned bytes are responsible for
//! wrapping that ownership in their own protected type.

#![cfg(any(windows, test))]

use zeroize::Zeroizing;

/// Keep each native read bounded while avoiding a second allocation for a
/// final one-byte bound probe.
pub(super) const STAGING_BYTES: usize = 16 * 1024;

pub(super) struct ProtectedPayload {
    bytes: Zeroizing<Vec<u8>>,
    #[cfg(test)]
    initial_allocation: (usize, usize),
}

#[derive(Debug)]
pub(super) enum ProtectedPayloadError<E> {
    Invalid(&'static str),
    Oversized,
    Source(E),
    Allocation,
}

impl ProtectedPayload {
    /// Read through a bounded source callback.
    ///
    /// The source receives a slice no larger than the remaining `max_bytes +
    /// 1` bound.  A single byte beyond `max_bytes` is retained only inside the
    /// zeroizing owner before the oversize error is returned, so no ordinary
    /// `Vec` reallocation can leave an old secret allocation behind.
    pub(super) fn read_with<E, F>(
        max_bytes: usize,
        mut read: F,
    ) -> Result<Self, ProtectedPayloadError<E>>
    where
        F: FnMut(&mut [u8]) -> Result<usize, E>,
    {
        if max_bytes == 0 {
            return Err(ProtectedPayloadError::Invalid(
                "protected payload bound must be nonzero",
            ));
        }
        let capacity = max_bytes
            .checked_add(1)
            .ok_or(ProtectedPayloadError::Invalid(
                "protected payload bound overflows",
            ))?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ProtectedPayloadError::Allocation)?;
        #[cfg(test)]
        let initial_allocation = (bytes.as_ptr() as usize, bytes.capacity());
        let mut staging = Zeroizing::new([0_u8; STAGING_BYTES]);

        loop {
            let remaining =
                capacity
                    .checked_sub(bytes.len())
                    .ok_or(ProtectedPayloadError::Invalid(
                        "protected payload length exceeds its allocation",
                    ))?;
            if remaining == 0 {
                return Err(ProtectedPayloadError::Oversized);
            }
            let count = remaining.min(STAGING_BYTES);
            let read = read(&mut staging[..count]).map_err(ProtectedPayloadError::Source)?;
            if read > count {
                return Err(ProtectedPayloadError::Invalid(
                    "protected payload source returned more bytes than requested",
                ));
            }
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&staging[..read]);
            if bytes.len() > max_bytes {
                return Err(ProtectedPayloadError::Oversized);
            }
        }

        Ok(Self {
            bytes,
            #[cfg(test)]
            initial_allocation,
        })
    }

    /// Transfer the completed allocation without copying secret bytes.
    ///
    /// The caller must immediately put the returned vector under its own
    /// zeroizing owner when it retains the payload.  The wrapper left behind
    /// contains only an empty vector and therefore has no secret to erase.
    pub(super) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut *self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{ProtectedPayload, ProtectedPayloadError, STAGING_BYTES};
    use zeroize::Zeroizing;

    fn chunked_reader(
        source: &[u8],
        chunk_size: usize,
    ) -> impl FnMut(&mut [u8]) -> Result<usize, ()> + '_ {
        let mut offset = 0;
        move |buffer| {
            let count = source
                .len()
                .saturating_sub(offset)
                .min(buffer.len())
                .min(chunk_size);
            if count == 0 {
                return Ok(0);
            }
            buffer[..count].copy_from_slice(&source[offset..offset + count]);
            offset += count;
            Ok(count)
        }
    }

    #[test]
    fn exact_bound_is_accepted_with_a_final_eof_probe() {
        let source = [0x41_u8; 32];
        let payload = ProtectedPayload::read_with(source.len(), chunked_reader(&source, 7))
            .expect("exact bound should be accepted");
        assert_eq!(payload.into_vec(), source);
    }

    #[test]
    fn zero_bound_is_rejected_before_allocating() {
        let result = ProtectedPayload::read_with(0, |_buffer| Ok::<usize, ()>(0));
        assert!(matches!(
            result,
            Err(ProtectedPayloadError::Invalid(
                "protected payload bound must be nonzero"
            ))
        ));
    }

    #[test]
    fn oversize_is_rejected_at_the_bounded_probe() {
        let source = [0x42_u8; 33];
        let result = ProtectedPayload::read_with(32, chunked_reader(&source, 7));
        assert!(matches!(result, Err(ProtectedPayloadError::Oversized)));
    }

    #[test]
    fn source_error_drops_the_zeroizing_buffers() {
        let mut calls = 0;
        let result = ProtectedPayload::read_with(32, |buffer| {
            calls += 1;
            if calls == 1 {
                buffer[..4].copy_from_slice(b"safe");
                Ok(4)
            } else {
                Err("read failed")
            }
        });
        assert!(matches!(
            result,
            Err(ProtectedPayloadError::Source("read failed"))
        ));
        assert_eq!(calls, 2);
    }

    #[test]
    fn backing_owner_is_zeroizing_and_preallocated_to_bound_plus_one() {
        fn assert_zeroizing_vec(_: &Zeroizing<Vec<u8>>) {}

        let payload = ProtectedPayload::read_with(37, chunked_reader(&[0x43; 37], 5))
            .expect("bounded payload should be readable");
        assert_zeroizing_vec(&payload.bytes);
        assert!(payload.bytes.capacity() >= 38);
        assert_eq!(
            (payload.bytes.as_ptr() as usize, payload.bytes.capacity()),
            payload.initial_allocation,
            "bounded appends must not reallocate the secret backing store"
        );
        assert_eq!(STAGING_BYTES, 16 * 1024);
    }
}

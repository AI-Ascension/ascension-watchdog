//! Bounded systemd descriptor-transfer transport.
//!
//! A processed notification is NOT proof that PID 1 accepted a descriptor into
//! its store. The native owner must independently verify the exact stored
//! descriptor before publishing a recoverable launch acknowledgement.

use super::{BrokerError, BrokerResult, LaunchReceipt, MAX_FRAME_BYTES, hex_digest, remaining};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fd::{AsFd, BorrowedFd};
use rustix::io::Errno;
use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
use rustix::pipe::{PipeFlags, pipe_with};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::unix::net::UnixDatagram;
use std::time::Instant;

#[path = "descriptor_store_snapshot.rs"]
pub(crate) mod snapshot;

/// A bounded name binding the complete durable receipt, excluding its
/// transport-only duplicate flag. Names do not authenticate descriptors.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DescriptorName(String);

impl DescriptorName {
    pub fn for_receipt(receipt: &LaunchReceipt) -> BrokerResult<Self> {
        let mut receipt = receipt.clone();
        receipt.duplicate = false;
        let bytes = serde_json::to_vec(&receipt)
            .map_err(|error| BrokerError::Invalid(error.to_string()))?;
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(BrokerError::Invalid(
                "descriptor receipt exceeds frame bound".to_owned(),
            ));
        }
        Self::parse(&format!("cg-{}", hex_digest(&Sha256::digest(bytes))))
    }

    pub fn parse(name: &str) -> BrokerResult<Self> {
        if name.len() != 67
            || !name.starts_with("cg-")
            || name.as_bytes()[3..]
                .iter()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(BrokerError::Invalid(
                "descriptor name is not canonical".to_owned(),
            ));
        }
        Ok(Self(name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Only confirms the manager released a barrier fd after the notification.
/// Acceptance still requires an exact manager-side descriptor-store query.
#[derive(Debug)]
#[must_use]
pub struct NotificationProcessed {
    _private: (),
}

pub struct DescriptorStoreTransport {
    socket: UnixDatagram,
}

impl DescriptorStoreTransport {
    /// The caller supplies a connected, independently authenticated manager
    /// endpoint. This transport never chooses a fallback or authenticates a
    /// manager merely because it can receive datagrams.
    pub fn from_connected(socket: UnixDatagram) -> BrokerResult<Self> {
        socket.peer_addr().map_err(super::io_error)?;
        socket.set_nonblocking(true).map_err(super::io_error)?;
        Ok(Self { socket })
    }

    pub fn submit(
        &self,
        name: &DescriptorName,
        directory: &File,
        deadline: Instant,
    ) -> BrokerResult<NotificationProcessed> {
        if !directory.metadata().map_err(super::io_error)?.is_dir() {
            return Err(BrokerError::Invalid(
                "stored containment descriptor is not a directory".to_owned(),
            ));
        }
        let message = format!("FDSTORE=1\nFDPOLL=0\nFDNAME={}\n", name.as_str());
        self.send(&message, Some(directory.as_fd()), deadline)?;
        self.barrier(deadline)
    }

    pub fn remove(
        &self,
        name: &DescriptorName,
        deadline: Instant,
    ) -> BrokerResult<NotificationProcessed> {
        self.send(
            &format!("FDSTOREREMOVE=1\nFDNAME={}\n", name.as_str()),
            None,
            deadline,
        )?;
        self.barrier(deadline)
    }

    fn send(
        &self,
        message: &str,
        descriptor: Option<BorrowedFd<'_>>,
        deadline: Instant,
    ) -> BrokerResult<()> {
        loop {
            remaining(deadline)?;
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut ancillary = SendAncillaryBuffer::new(&mut space);
            let descriptors: Vec<_> = descriptor.into_iter().collect();
            if !descriptors.is_empty()
                && !ancillary.push(SendAncillaryMessage::ScmRights(&descriptors))
            {
                return Err(BrokerError::Unavailable(
                    "descriptor ancillary buffer is too small".to_owned(),
                ));
            }
            match sendmsg(
                &self.socket,
                &[IoSlice::new(message.as_bytes())],
                &mut ancillary,
                SendFlags::DONTWAIT | SendFlags::NOSIGNAL,
            ) {
                Ok(count) if count == message.len() => return Ok(()),
                Ok(_) => {
                    return Err(BrokerError::Unavailable(
                        "descriptor notification was truncated".to_owned(),
                    ));
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => wait(self.socket.as_fd(), PollFlags::OUT, deadline)?,
                Err(error) => return Err(BrokerError::Io(error.to_string())),
            }
        }
    }

    fn barrier(&self, deadline: Instant) -> BrokerResult<NotificationProcessed> {
        let (reader, writer) = pipe_with(PipeFlags::CLOEXEC | PipeFlags::NONBLOCK)
            .map_err(|error| BrokerError::Io(error.to_string()))?;
        // BARRIER is a separate message with exactly one fd. Keeping our own
        // writer open after sending would prevent acknowledgement via EOF.
        self.send("BARRIER=1\n", Some(writer.as_fd()), deadline)?;
        drop(writer);
        loop {
            remaining(deadline)?;
            match rustix::io::read(&reader, &mut [0_u8; 1]) {
                Ok(0) => return Ok(NotificationProcessed { _private: () }),
                Ok(_) => {
                    return Err(BrokerError::Conflict(
                        "descriptor barrier returned unexpected data".to_owned(),
                    ));
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => wait(reader.as_fd(), PollFlags::IN, deadline)?,
                Err(error) => return Err(BrokerError::Io(error.to_string())),
            }
        }
    }
}

fn wait(descriptor: BorrowedFd<'_>, events: PollFlags, deadline: Instant) -> BrokerResult<()> {
    loop {
        let timeout = Timespec::try_from(remaining(deadline)?).map_err(|_| {
            BrokerError::Unavailable("descriptor deadline exceeds native bounds".to_owned())
        })?;
        let mut descriptors = [PollFd::new(&descriptor, events)];
        match poll(&mut descriptors, Some(&timeout)) {
            Ok(0) => {
                remaining(deadline)?;
            }
            Ok(_) => {
                if descriptors[0].revents().contains(PollFlags::NVAL) {
                    return Err(BrokerError::Unavailable(
                        "descriptor became invalid while waiting".to_owned(),
                    ));
                }
                return Ok(());
            }
            Err(Errno::INTR) => {}
            Err(error) => return Err(BrokerError::Io(error.to_string())),
        }
    }
}

#[cfg(test)]
#[path = "descriptor_store_tests.rs"]
mod tests;

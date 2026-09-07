//! Absolute transport deadlines for the single-threaded synthetic peer.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(2);

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "fixture transport deadline"))
}

pub(crate) struct DeadlineReader {
    stream: TcpStream,
    deadline: Instant,
}

impl DeadlineReader {
    pub(crate) fn new(stream: &TcpStream, deadline: Instant) -> io::Result<Self> {
        Ok(Self {
            stream: stream.try_clone()?,
            deadline,
        })
    }
}

impl Read for DeadlineReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(bytes)
    }
}

pub(crate) fn write_bytes(stream: &mut TcpStream, mut bytes: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + IO_TIMEOUT;
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(remaining(deadline)?))?;
        match stream.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(crate) fn is_peer_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn expired_deadline_rejects_even_already_available_bytes() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut peer = TcpStream::connect_timeout(&listener.local_addr()?, IO_TIMEOUT)?;
        let (stream, _) = listener.accept()?;
        peer.write_all(b"available")?;
        let mut reader = DeadlineReader::new(&stream, Instant::now())?;
        let error = reader.read(&mut [0; 1]).expect_err("deadline expired");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        Ok(())
    }

    #[test]
    fn nonreading_peer_cannot_hold_a_writer_indefinitely() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut peer = TcpStream::connect_timeout(&listener.local_addr()?, IO_TIMEOUT)?;
        let (_nonreading, _) = listener.accept()?;
        // Exceed the local TCP send buffer without depending on native socket
        // options. This test payload is not an exposed fixture frame.
        let bytes = vec![0; 16 * 1024 * 1024];
        let started = Instant::now();
        let error = write_bytes(&mut peer, &bytes).expect_err("peer never drains");
        assert!(is_peer_error(&error));
        assert!(started.elapsed() < Duration::from_secs(4));
        Ok(())
    }
}

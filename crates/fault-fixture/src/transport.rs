//! Absolute transport deadlines for the single-threaded synthetic peer.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum connect attempts for one logical client request.
///
/// A loopback handshake can exceed a single [`IO_TIMEOUT`] budget on a loaded
/// runner even though the peer is healthy (observed as `WSAETIMEDOUT`, OS error
/// 10060, on `windows-latest` in issue #204). Retrying the *connect* is safe: no
/// request bytes have been written yet, so a retry can never replay a mutation.
/// Only `TimedOut` is retried; every other failure is surfaced immediately so a
/// genuinely absent peer still fails fast.
pub(crate) const CONNECT_ATTEMPTS: u32 = 4;

/// Bounded pause between connect attempts; keeps retries from busy-looping.
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_millis(50);

/// Retry a transient connect failure up to [`CONNECT_ATTEMPTS`] times.
///
/// `attempt` receives the 1-based attempt number and returns the connect
/// result. The loop returns the first success, the first non-timeout error as
/// is, or the final timeout once the attempt cap is reached.
fn retry_timed_out_connect<T, F>(mut attempt: F) -> io::Result<T>
where
    F: FnMut(u32) -> io::Result<T>,
{
    let mut index = 1;
    loop {
        match attempt(index) {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == io::ErrorKind::TimedOut && index < CONNECT_ATTEMPTS => {
                index += 1;
                std::thread::sleep(CONNECT_RETRY_BACKOFF);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Connect to the fixture peer, retrying a timed-out loopback handshake.
pub(crate) fn connect_bounded(address: &SocketAddr) -> io::Result<TcpStream> {
    retry_timed_out_connect(|_| TcpStream::connect_timeout(address, IO_TIMEOUT))
}

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

pub(crate) fn write_bytes(stream: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    write_bytes_until(stream, bytes, Instant::now() + IO_TIMEOUT)
}

// Connections are blocking and single-owner outside this write phase. Restoring
// that mode keeps subsequent read handling unchanged on both success and failure.
fn write_bytes_until(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    const WRITE_CHUNK_BYTES: usize = 16 * 1024;
    stream.set_nonblocking(true)?;
    let result = (|| {
        while !bytes.is_empty() {
            remaining(deadline)?;
            let chunk = &bytes[..bytes.len().min(WRITE_CHUNK_BYTES)];
            match stream.write(chunk) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => bytes = &bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(1)));
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    })();
    let restore = stream.set_nonblocking(false);
    match (result, restore) {
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
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
    use socket2::{Domain, SockAddr, SockRef, Socket, Type};
    use std::net::{SocketAddr, TcpListener};

    #[test]
    fn bounded_connect_succeeds_after_one_transient_timeout() -> io::Result<()> {
        let mut attempts = 0;
        let value = retry_timed_out_connect(|_| {
            attempts += 1;
            if attempts == 1 {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "first loopback handshake stalls",
                ))
            } else {
                Ok(7_u8)
            }
        })?;
        assert_eq!(value, 7);
        assert_eq!(attempts, 2);
        Ok(())
    }

    #[test]
    fn bounded_connect_stops_after_the_attempt_cap() {
        let mut attempts = 0;
        let error = retry_timed_out_connect(|_| {
            attempts += 1;
            Err::<u8, io::Error>(io::Error::new(io::ErrorKind::TimedOut, "always stalls"))
        })
        .expect_err("the final timeout must surface");
        assert_eq!(attempts, CONNECT_ATTEMPTS);
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn bounded_connect_does_not_retry_a_non_timeout_failure() {
        let mut attempts = 0;
        let error = retry_timed_out_connect(|_| {
            attempts += 1;
            Err::<u8, io::Error>(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "absent peer",
            ))
        })
        .expect_err("refused peers must not be retried");
        assert_eq!(attempts, 1);
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    }

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
    fn expired_write_deadline_rejects_a_writable_socket() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut writer = TcpStream::connect_timeout(&listener.local_addr()?, IO_TIMEOUT)?;
        let (mut receiver, _) = listener.accept()?;
        let error = write_bytes_until(&mut writer, b"must-not-send", Instant::now())
            .expect_err("an expired budget cannot send even immediately writable bytes");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        receiver.set_nonblocking(true)?;
        assert_eq!(
            receiver
                .read(&mut [0; 1])
                .expect_err("no bytes sent")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        Ok(())
    }

    #[test]
    fn nonreading_peer_cannot_hold_a_writer_indefinitely() -> io::Result<()> {
        #[cfg(windows)]
        const RECEIVE_BUFFER_BYTES: usize = 0;
        #[cfg(not(windows))]
        const RECEIVE_BUFFER_BYTES: usize = 4 * 1024;
        const SEND_BUFFER_BYTES: usize = 4 * 1024;
        const MAX_PREFILL_BYTES: usize = 1024 * 1024;
        let listener_socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
        listener_socket.set_recv_buffer_size(RECEIVE_BUFFER_BYTES)?;
        listener_socket.bind(&SockAddr::from(SocketAddr::from(([127, 0, 0, 1], 0))))?;
        listener_socket.listen(1)?;
        let listener: TcpListener = listener_socket.into();
        let mut peer = TcpStream::connect_timeout(&listener.local_addr()?, IO_TIMEOUT)?;
        listener.set_nonblocking(true)?;
        let accept_deadline = Instant::now() + IO_TIMEOUT;
        let (nonreading, _) = loop {
            remaining(accept_deadline)?;
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(remaining(accept_deadline)?.min(Duration::from_millis(1)));
                }
                Err(error) => return Err(error),
            }
        };
        {
            let socket = SockRef::from(&nonreading);
            socket.set_recv_buffer_size(RECEIVE_BUFFER_BYTES)?;
        }
        let send_buffer_bytes = {
            let socket = SockRef::from(&peer);
            socket.set_send_buffer_size(SEND_BUFFER_BYTES)?;
            socket.send_buffer_size()?
        };
        let receive_buffer_bytes = {
            let socket = SockRef::from(&nonreading);
            socket.recv_buffer_size()?
        };
        // Never read from the accepted peer. Observe real backpressure before
        // testing the deadline; socket buffer settings alone do not prove the
        // effective capacity on every platform.
        let effective_buffer_bytes = send_buffer_bytes.saturating_add(receive_buffer_bytes);
        assert!(effective_buffer_bytes <= MAX_PREFILL_BYTES / 4);
        let chunk = vec![0; 1024];
        peer.set_nonblocking(true)?;
        let mut prefilled_bytes = 0;
        let mut backpressure_observed = false;
        let prefill_deadline = Instant::now() + IO_TIMEOUT;
        while prefilled_bytes < MAX_PREFILL_BYTES && Instant::now() < prefill_deadline {
            match peer.write(&chunk) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) => prefilled_bytes += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    backpressure_observed = true;
                    break;
                }
                Err(error) => return Err(error),
            }
        }
        peer.set_nonblocking(false)?;
        assert!(
            backpressure_observed,
            "nonreading peer accepted the bounded prefill ({prefilled_bytes} bytes)"
        );
        let bytes = vec![0; MAX_PREFILL_BYTES];
        let started = Instant::now();
        let error = write_bytes(&mut peer, &bytes).expect_err("peer never drains");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        assert!(started.elapsed() < Duration::from_secs(4));
        Ok(())
    }
}

//! Test-only broker peer fixture.
//!
//! The linux broker authenticates a peer by hashing that peer's own executable
//! through `/proc/<pid>/exe` under a bounded deadline, and it re-hashes on
//! every authenticated call.  When the unit-test process is itself the peer -
//! which is what `UnixStream::pair()` forces, because `SO_PEERCRED` on a
//! socket pair always reports the process that created the socket - the
//! hashed object is the whole test executable.  That is a hundred megabytes
//! of debug info, so a correctness deadline ends up measuring build-profile
//! size and disk contention rather than the work under test.
//!
//! This helper gives those tests a peer whose executable is a few megabytes of
//! trivially-linked code instead: it connects to the broker's listening socket
//! itself, which is what makes the kernel report *its* PID as the peer, and
//! then relays one request from stdin and the broker's reply to stdout.
//!
//! It holds no authority.  It is not the broker, not a service, and it is
//! never installed or launched outside the test suite.  The broker's
//! authentication is unchanged and still runs in full against this process -
//! the pidfd pin, the process-start-token check, the `MAX_HASH_BYTES` bound and
//! the deadline enforcement all still apply, they simply apply to a small
//! object instead of a hundred-megabyte one.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

fn main() {
    let Some(socket) = std::env::args_os().nth(1) else {
        eprintln!("broker-peer-fixture: socket path argument is required");
        std::process::exit(2);
    };
    if let Err(error) = relay(&socket) {
        eprintln!("broker-peer-fixture: {error}");
        std::process::exit(1);
    }
}

fn relay(socket: &std::ffi::OsStr) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    // Stream the request rather than buffering it, then half-close so the
    // broker observes end-of-request and answers.
    let relayed = std::io::copy(&mut std::io::stdin().lock(), &mut stream);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    relayed?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&response)?;
    stdout.flush()
}

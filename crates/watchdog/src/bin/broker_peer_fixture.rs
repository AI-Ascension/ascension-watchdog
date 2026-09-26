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
//! trivially-linked code instead.  It connects to the broker's listening
//! socket itself, which is what makes the kernel report *its* PID as the
//! peer, relays one request from stdin, and writes the broker's reply to a
//! file so the test can collect it after the broker call has finished.
//!
//! It holds no authority.  It is not the broker, not a service, and it is
//! never installed or launched outside the test suite.  The broker's
//! authentication is unchanged and still runs in full against this process -
//! the pidfd pin, the process-start-token check, the `MAX_HASH_BYTES` bound and
//! the deadline enforcement all still apply, they simply apply to a small
//! object instead of a hundred-megabyte one.
//!
//! Usage: `broker-peer-fixture SOCKET REPLY_PATH RELEASE_PATH CLOSED_PATH [DROP_REPLY]`.
//!
//! With `DROP_REPLY`, the helper closes the connection instead of relaying the
//! broker's answer, so the test can observe what the broker does when a peer
//! vanishes mid-request.
//!
//! `CLOSED_PATH` is created immediately after the helper stops using the
//! socket.  A Unix socket write only fails once the peer has been closed, so a
//! test that needs the broker to observe a lost response waits for that file
//! before calling the broker; without it the broker's answer can land in the
//! kernel buffer and the "peer vanished" case would pass for the wrong reason.
//!
//! The helper stays alive until `RELEASE_PATH` appears, so the peer process
//! still exists for every `authenticate_peer` call the broker makes - the
//! broker re-authenticates on each call, and a helper that exited early would
//! make the pidfd pin fail for reasons unrelated to what is under test.
//!
//! It is a Linux-only peer, so on other targets the binary is still declared
//! (the crate's `cargo build --bins` gate builds it everywhere) but refuses to
//! run rather than pretending to relay a `SO_PEERCRED` peer it cannot spawn.

#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    let (Some(socket), Some(reply), Some(release)) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        eprintln!(
            "broker-peer-fixture: SOCKET, REPLY_PATH, RELEASE_PATH and CLOSED_PATH arguments are required"
        );
        std::process::exit(2);
    };
    let Some(closed) = arguments.next() else {
        eprintln!("broker-peer-fixture: CLOSED_PATH argument is required");
        std::process::exit(2);
    };
    let drop_reply = arguments
        .next()
        .is_some_and(|argument| argument == "DROP_REPLY");
    if let Err(error) = run(
        &socket,
        Path::new(&reply),
        PathBuf::from(release),
        PathBuf::from(closed),
        drop_reply,
    ) {
        eprintln!("broker-peer-fixture: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("broker-peer-fixture is only available on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn run(
    socket: &std::ffi::OsStr,
    reply: &std::path::Path,
    release: PathBuf,
    closed: PathBuf,
    drop_reply: bool,
) -> std::io::Result<()> {
    let mut stream = UnixStream::connect(socket)?;
    // Stream the request rather than buffering it, then half-close so the
    // broker observes end-of-request and answers.
    let relayed = std::io::copy(&mut std::io::stdin().lock(), &mut stream);
    let _ = stream.shutdown(std::net::Shutdown::Write);
    relayed?;
    if drop_reply {
        // Model a peer that disappears before the broker answers.  Closing
        // the socket is what the broker observes; the process itself then
        // lingers until released so a later `authenticate_peer` still finds a
        // live peer, exactly as the test's follow-up inspect/stop calls need.
        drop(stream);
        std::fs::File::create(&closed)?;
        wait_for_release(&release)?;
        return Ok(());
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let mut file = std::fs::File::create(reply)?;
    file.write_all(&response)?;
    file.flush()?;
    drop(stream);
    std::fs::File::create(&closed)?;
    wait_for_release(&release)
}

#[cfg(target_os = "linux")]
fn wait_for_release(release: &Path) -> std::io::Result<()> {
    for _ in 0..600_000 {
        if release.exists() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "broker peer helper was never released",
    ))
}

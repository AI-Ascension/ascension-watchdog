//! Server lifecycle support for the runtime-v3 integration tests.
//!
//! Extracted verbatim from `tests/runtime.rs`; only visibility was widened to
//! `pub(super)` so the crate-root test functions keep observing the same state.

use std::io::{BufRead, BufReader, Read};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use fault_fixture::{Client, Frame};
use serde_json::json;
use uuid::Uuid;

pub(super) struct RunningServer {
    pub(super) child: Child,
    pub(super) address: SocketAddr,
    pub(super) database: PathBuf,
}

impl RunningServer {
    pub(super) fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let database = std::env::temp_dir().join(format!(
            "watchdog-runtime-fixture-{}.sqlite",
            Uuid::new_v4()
        ));
        Self::start_on_database(database)
    }

    pub(super) fn start_on_database(database: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let child = Command::new(env!("CARGO_BIN_EXE_fault-fixture-server"))
            .arg("--db")
            .arg(&database)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        // Own cleanup immediately after spawn, including announcement failures
        // and assertion unwinding in the calling test.
        let mut server = Self {
            child,
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            database,
        };
        let stdout = server
            .child
            .stdout
            .take()
            .ok_or("server stdout unavailable")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        server.address = line
            .strip_prefix("LISTEN ")
            .ok_or("server did not announce its listener")?
            .trim()
            .parse()?;
        Ok(server)
    }

    pub(super) fn stop(mut self) -> Result<(), Box<dyn std::error::Error>> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let _ = self.child.wait();
        remove_database(&self.database);
        Ok(())
    }

    pub(super) fn crash_preserving_database(
        mut self,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if self.child.try_wait()?.is_none() {
            self.child.kill()?;
        }
        let _ = self.child.wait()?;
        let database = self.database.clone();
        // The replacement process needs the durable files. The child has
        // already been reaped, so forgetting only this test owner avoids its
        // normal cleanup path until the replacement stops.
        std::mem::forget(self);
        Ok(database)
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        // Child::kill targets the still-owned handle, never a discovered PID.
        // Reap before removing this fixture's uniquely named database files.
        let _ = self.child.kill();
        let _ = self.child.wait();
        remove_database(&self.database);
    }
}

pub(super) fn remove_database(path: &PathBuf) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(path.with_extension("sqlite-shm"));
    let _ = std::fs::remove_file(path.with_extension("sqlite.lock"));
}

pub(super) fn assert_connection_closed(
    peer: &mut TcpStream,
) -> Result<(), Box<dyn std::error::Error>> {
    peer.set_read_timeout(Some(Duration::from_secs(4)))?;
    match peer.read(&mut [0; 1]) {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => Ok(()),
        other => Err(format!("expected bounded peer close, got {other:?}").into()),
    }
}

pub(super) fn assert_server_healthy(
    server: &RunningServer,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = Client::new(server.address).request(&Frame::request(
        "stats",
        "recovery_read",
        json!({}),
    ))?;
    assert_eq!(response.kind, "stats_response");
    Ok(())
}

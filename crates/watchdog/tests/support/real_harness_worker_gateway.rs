// SPDX-License-Identifier: MIT

//! Owner-local downstream gateway fixture for the real harness smoke.

use std::io::{self, Write};
use std::net::{Shutdown, TcpListener};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::Duration;

const HOLD_GATEWAY_ENV: &str = "ASCENSION_WATCHDOG_REAL_HARNESS_HOLD_GATEWAY";

/// A fixture-owned loopback gateway that answers every request with a bounded
/// rejection. Keeping the listener alive for the whole child lifetime makes
/// the selected port an owned test resource rather than an unowned port
/// assumption, while still exercising the harness HTTP failure path.
pub(super) struct GatewayFixture {
    address: String,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl GatewayFixture {
    pub(super) fn new() -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let hold_response = std::env::var(HOLD_GATEWAY_ENV).as_deref() == Ok("1");
        let thread_stop = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _peer)) => {
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(250)));
                        if hold_response {
                            // Keep the runtime child inside its admitted
                            // worker handoff until the watchdog's explicit
                            // stop path exercises cgroup cancellation.  The
                            // short bounded wait still lets a non-stopping
                            // test finish with the normal 503 fixture.
                            for _ in 0..200 {
                                if thread_stop.load(Ordering::Acquire) {
                                    break;
                                }
                                thread::sleep(Duration::from_millis(10));
                            }
                        }
                        let _ =
                            stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\n".as_slice());
                        let _ = stream.write_all(
                            b"Content-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
                        );
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            stop,
            thread: Some(thread),
        })
    }

    pub(super) fn address(&self) -> &str {
        &self.address
    }
}

impl Drop for GatewayFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

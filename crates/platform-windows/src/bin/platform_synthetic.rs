//! Small direct-process fixture used by the native Windows containment test.
//!
//! The fixture deliberately does not invoke a shell.  Its parent can create a
//! child with `std::process::Command`; the platform adapter must place both in
//! the same Job Object and terminate both through that authority.

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::thread;
use std::time::Duration;

fn main() {
    let mut arguments = env::args_os().skip(1);
    let Some(mode) = arguments.next() else {
        process::exit(2);
    };
    match mode.to_string_lossy().as_ref() {
        "--spawn-descendant" => {
            let Some(marker) = arguments.next().map(PathBuf::from) else {
                process::exit(2);
            };
            spawn_descendant(&marker);
        }
        "--descendant" => {
            let Some(marker) = arguments.next().map(PathBuf::from) else {
                process::exit(2);
            };
            let _ = fs::write(marker, process::id().to_string());
            loop_forever();
        }
        "--crash-after-ms" => {
            let Some(delay) = arguments
                .next()
                .and_then(|value| value.to_str().map(str::to_owned))
            else {
                process::exit(2);
            };
            let Ok(delay) = delay.parse::<u64>() else {
                process::exit(2);
            };
            thread::sleep(Duration::from_millis(delay));
            process::exit(41);
        }
        "--read-worker-bootstrap" => {
            let Some(marker) = arguments.next().map(PathBuf::from) else {
                process::exit(2);
            };
            read_worker_bootstrap(&marker);
        }
        "--read-gateway-health-bootstrap" => {
            let Some(marker) = arguments.next().map(PathBuf::from) else {
                process::exit(2);
            };
            read_gateway_health_bootstrap(&marker);
        }
        _ => process::exit(2),
    }
}

fn read_worker_bootstrap(marker: &Path) -> ! {
    const MAGIC: &[u8; 8] = b"ASC-WB01";
    const PREFIX_BYTES: usize = 12;
    const MAX_PAYLOAD_BYTES: usize = 16_384;
    let mut stdin = io::stdin().lock();
    let mut prefix = [0_u8; PREFIX_BYTES];
    if stdin.read_exact(&mut prefix).is_err() || &prefix[..MAGIC.len()] != MAGIC {
        process::exit(2);
    }
    let payload_length = usize::try_from(u32::from_be_bytes([
        prefix[8], prefix[9], prefix[10], prefix[11],
    ]))
    .unwrap_or(0);
    if payload_length == 0 || payload_length > MAX_PAYLOAD_BYTES {
        process::exit(2);
    }
    let mut frame = prefix.to_vec();
    frame.resize(PREFIX_BYTES + payload_length, 0);
    if stdin.read_exact(&mut frame[PREFIX_BYTES..]).is_err() || fs::write(marker, &frame).is_err() {
        process::exit(2);
    }
    loop_forever();
}

fn read_gateway_health_bootstrap(marker: &Path) -> ! {
    const MAGIC: &[u8; 8] = b"STS2GH01";
    const FRAME_BYTES: usize = 56;
    let mut stdin = io::stdin().lock();
    let mut frame = [0_u8; FRAME_BYTES];
    if stdin.read_exact(&mut frame).is_err()
        || &frame[..MAGIC.len()] != MAGIC
        || frame[MAGIC.len()..MAGIC.len() + 16]
            .iter()
            .all(|byte| *byte == 0)
        || frame[MAGIC.len() + 16..].iter().all(|byte| *byte == 0)
        || fs::write(marker, frame).is_err()
    {
        process::exit(2);
    }
    loop_forever();
}

fn spawn_descendant(marker: &Path) -> ! {
    let executable = env::current_exe().unwrap_or_else(|_| process::exit(2));
    let mut child = Command::new(executable)
        .arg("--descendant")
        .arg(marker)
        .spawn()
        .unwrap_or_else(|_| process::exit(2));
    let parent_marker = marker.with_extension("parent.pid");
    let _ = fs::write(parent_marker, process::id().to_string());
    let child_marker = marker.with_extension("child.spawned");
    let _ = fs::write(child_marker, child.id().to_string());
    let status = child.wait().unwrap_or_else(|_| process::exit(2));
    process::exit(status.code().unwrap_or(42));
}

fn loop_forever() -> ! {
    loop {
        thread::sleep(Duration::from_millis(100));
    }
}

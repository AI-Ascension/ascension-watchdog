//! Small direct-process fixture used by the native Windows containment test.
//!
//! The fixture deliberately does not invoke a shell.  Its parent can create a
//! child with `std::process::Command`; the platform adapter must place both in
//! the same Job Object and terminate both through that authority.

use std::env;
use std::fs;
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
        _ => process::exit(2),
    }
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

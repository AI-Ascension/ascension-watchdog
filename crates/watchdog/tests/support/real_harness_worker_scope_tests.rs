// SPDX-License-Identifier: MIT

//! Synthetic checks of helper bounds; these do not start a systemd scope.

use super::{
    MAX_COMMAND_OUTPUT, join_command_output, open_cgroup_directory, open_cgroup_events, run_bounded,
};
use std::fs;
use std::io;
use std::io::Read;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn helper_timeout_reaps_the_owned_process_within_a_bound() {
    let mut command = Command::new("/usr/bin/sleep");
    command.arg("5").env_clear();
    let started = Instant::now();
    let error = run_bounded(command, Duration::from_millis(20))
        .expect_err("sleeping helper must hit its deadline");
    assert!(error.to_string().contains("bounded timeout"));
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[test]
fn helper_output_larger_than_a_pipe_is_drained_and_capped() {
    let mut command = Command::new("/usr/bin/head");
    command.args(["-c", "262144", "/dev/zero"]).env_clear();
    let (failed, output) =
        run_bounded(command, Duration::from_secs(2)).expect("bounded output producer must settle");
    assert!(!failed);
    assert_eq!(output.len(), MAX_COMMAND_OUTPUT);
}

#[test]
fn combined_output_truncation_preserves_utf8_boundaries() {
    let stdout = thread::spawn(|| Ok::<_, io::Error>(vec![b'x'; MAX_COMMAND_OUTPUT - 1]));
    let stderr = thread::spawn(|| Ok::<_, io::Error>("é".as_bytes().to_vec()));
    let output = join_command_output(stdout, stderr).expect("UTF-8-safe bounded output");
    assert!(output.ends_with("...[truncated]"));
    assert_eq!(
        output.len(),
        MAX_COMMAND_OUTPUT - 1 + "...[truncated]".len()
    );
}

#[cfg(unix)]
#[test]
fn cgroup_events_handle_stays_bound_to_original_directory() {
    let directory = tempfile::tempdir().expect("temporary cgroup analogue");
    let original = directory.path().join("scope");
    fs::create_dir(&original).expect("create original directory");
    fs::write(original.join("cgroup.events"), "populated 0\n").expect("write original events");

    let retained_directory = open_cgroup_directory(&original).expect("retain directory handle");
    let retained_events = open_cgroup_events(&retained_directory).expect("retain events handle");

    fs::remove_file(original.join("cgroup.events")).expect("remove original events");
    fs::remove_dir(&original).expect("remove original directory");
    fs::create_dir(&original).expect("recreate directory at same path");
    fs::write(original.join("cgroup.events"), "populated 1\n").expect("write replacement events");

    let mut retained_text = String::new();
    (&retained_events)
        .take(4096)
        .read_to_string(&mut retained_text)
        .expect("read retained original events");
    assert_eq!(retained_text, "populated 0\n");
    assert_eq!(
        fs::read_to_string(original.join("cgroup.events")).expect("read replacement events"),
        "populated 1\n"
    );
}

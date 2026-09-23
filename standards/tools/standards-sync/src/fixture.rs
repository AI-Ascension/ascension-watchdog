//! Unique temporary fixture directories for conformance and unit tests.

use crate::Result;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::path::PathBuf;

pub(crate) fn create_fixture_directory() -> Result<PathBuf> {
    let base = std::env::temp_dir();
    let pid = std::process::id();
    for attempt in 0..1000u32 {
        let root = base.join(format!("standards-sync-fixture-{pid}-{attempt}"));
        let marker = root.with_extension("creating");
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
        {
            Ok(file) => {
                drop(file);
                let result = fs::create_dir(&root);
                let _ = fs::remove_file(&marker);
                match result {
                    Ok(()) => return Ok(root),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(format!(
                            "cannot create unique fixture directory {}: {error}",
                            root.display()
                        ));
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot reserve unique fixture directory {}: {error}",
                    marker.display()
                ));
            }
        }
    }
    Err("cannot reserve a unique fixture directory after 1000 attempts".to_owned())
}

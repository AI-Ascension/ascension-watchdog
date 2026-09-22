//! Retained cgroup-v2 handles and process/scope identity checks.

use super::CGROUP_MOUNT;
use super::paths::sha256_file;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) fn cgroup_path(control_group: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if !control_group.starts_with('/') || control_group.contains("..") {
        return Err(io::Error::other("unsafe systemd cgroup path").into());
    }
    Ok(Path::new(CGROUP_MOUNT).join(control_group.trim_start_matches('/')))
}

pub(crate) fn require_cgroup_v2() -> Result<(), Box<dyn std::error::Error>> {
    for name in ["cgroup.controllers", "cgroup.procs"] {
        let path = Path::new(CGROUP_MOUNT).join(name);
        if !path.is_file() {
            return Err(io::Error::other(format!(
                "required cgroup-v2 file is unavailable: {}",
                path.display()
            ))
            .into());
        }
    }
    Ok(())
}

/// The cgroup directory and events file are opened while the live scope is
/// admitted and retained until stop proof is written.  Looking up the path on
/// every poll is insufficient: systemd can remove it and a later unit can
/// recreate the same pathname for a different cgroup.
pub(crate) struct OriginalCgroup {
    pub(crate) control_group: String,
    directory: File,
    events: File,
    directory_dev: u64,
    directory_ino: u64,
    events_dev: u64,
    events_ino: u64,
}

pub(crate) fn open_cgroup_directory(path: &Path) -> io::Result<File> {
    Ok(File::from(rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::CLOEXEC
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )?))
}

pub(crate) fn open_cgroup_events(directory: &File) -> io::Result<File> {
    Ok(File::from(rustix::fs::openat(
        directory.as_fd(),
        "cgroup.events",
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?))
}

impl OriginalCgroup {
    pub(crate) fn open(control_group: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let path = cgroup_path(control_group)?;
        let directory = open_cgroup_directory(&path)?;
        let directory_metadata = directory.metadata()?;
        if !directory_metadata.is_dir() {
            return Err(io::Error::other("original cgroup path is not a directory").into());
        }
        // Open events relative to the retained directory descriptor.  A
        // pathname open here could pair an old directory with a newly
        // recreated cgroup.events file after a remove/recreate race.
        let events = open_cgroup_events(&directory)?;
        let events_metadata = events.metadata()?;
        if events_metadata.dev() != directory_metadata.dev() {
            return Err(io::Error::other("cgroup.events is on a different filesystem").into());
        }
        let original = Self {
            control_group: control_group.to_owned(),
            directory,
            events,
            directory_dev: directory_metadata.dev(),
            directory_ino: directory_metadata.ino(),
            events_dev: events_metadata.dev(),
            events_ino: events_metadata.ino(),
        };
        if original.verify_path()? {
            return Err(io::Error::other("original cgroup was removed during admission").into());
        }
        Ok(original)
    }

    pub(crate) fn verify_retained_handles(&self) -> io::Result<()> {
        let directory = self.directory.metadata()?;
        if !directory.is_dir()
            || directory.dev() != self.directory_dev
            || directory.ino() != self.directory_ino
        {
            return Err(io::Error::other(
                "retained cgroup directory identity changed",
            ));
        }
        let events = self.events.metadata()?;
        if events.dev() != self.events_dev || events.ino() != self.events_ino {
            return Err(io::Error::other("retained cgroup.events identity changed"));
        }
        Ok(())
    }

    /// Return whether the original pathname is still the original inode.
    /// `false` means it is present; `true` means it was positively unlinked.
    pub(crate) fn verify_path(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let path = cgroup_path(&self.control_group)?;
        match fs::metadata(path) {
            Ok(metadata) => {
                if !metadata.is_dir()
                    || metadata.dev() != self.directory_dev
                    || metadata.ino() != self.directory_ino
                {
                    return Err(io::Error::other(
                        "current cgroup path does not identify the admitted cgroup",
                    )
                    .into());
                }
                self.verify_retained_handles()?;
                Ok(false)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound || is_enodev(&error) => {
                // Once systemd removes a cgroup, a retained directory or
                // events descriptor may report ENODEV rather than remaining
                // stat-able.  Accept that only after the original pathname
                // is gone and the descriptor identifies this same cgroup (or
                // the kernel has positively invalidated that descriptor).
                match self.directory.metadata() {
                    Ok(metadata)
                        if metadata.is_dir()
                            && metadata.dev() == self.directory_dev
                            && metadata.ino() == self.directory_ino => {}
                    Err(error) if is_enodev(&error) => return Ok(true),
                    Ok(_) => {
                        return Err(
                            io::Error::other("retained cgroup directory identity changed").into(),
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
                match self.events.metadata() {
                    Ok(metadata)
                        if metadata.dev() == self.events_dev
                            && metadata.ino() == self.events_ino => {}
                    Err(error) if is_enodev(&error) => return Ok(true),
                    Ok(_) => {
                        return Err(
                            io::Error::other("retained cgroup.events identity changed").into()
                        );
                    }
                    Err(error) => return Err(error.into()),
                }
                Ok(true)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn empty(&mut self) -> Result<bool, Box<dyn std::error::Error>> {
        let unlinked = self.verify_path()?;
        if let Err(error) = self.events.seek(SeekFrom::Start(0)) {
            if is_enodev(&error) {
                // A removed cgroup can invalidate an already-open events
                // descriptor between verify_path and seek.  Recheck the
                // pathname so ENODEV is accepted only with positive proof
                // that this exact retained cgroup was unlinked.
                return self.verify_path();
            }
            return Err(error.into());
        }
        let mut text = String::new();
        match self.events.read_to_string(&mut text) {
            Ok(_) => {}
            Err(error) if is_enodev(&error) => {
                // An ENODEV events read is not itself proof of emptiness. It
                // is accepted only when retained metadata proves this exact
                // cgroup was unlinked, which is a positive stop observation.
                return Ok(unlinked);
            }
            Err(error) => return Err(error.into()),
        }
        let populated = text
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
            .ok_or_else(|| io::Error::other("cgroup.events lacks populated state"))?;
        match populated {
            "0" => Ok(true),
            "1" => Ok(false),
            value => Err(io::Error::other(format!(
                "cgroup.events has invalid populated state {value:?}"
            ))
            .into()),
        }
    }
}

pub(crate) fn is_enodev(error: &io::Error) -> bool {
    error.raw_os_error() == io::Error::from(rustix::io::Errno::NODEV).raw_os_error()
}

pub(crate) fn process_cgroup(pid: u32) -> Result<String, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .filter(|path| path.starts_with('/'))
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            io::Error::other(format!("process {pid} has no cgroup-v2 membership")).into()
        })
}

pub(crate) fn process_in_scope(
    pid: u32,
    control_group: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let path = process_cgroup(pid)?;
    Ok(path == control_group || path.starts_with(&format!("{control_group}/")))
}

pub(crate) fn process_matches_image(
    pid: u32,
    image: &Path,
    digest: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let exe = fs::read_link(format!("/proc/{pid}/exe"))?;
    let canonical = fs::canonicalize(exe)?;
    if canonical != image {
        return Ok(false);
    }
    Ok(sha256_file(&canonical)? == digest)
}

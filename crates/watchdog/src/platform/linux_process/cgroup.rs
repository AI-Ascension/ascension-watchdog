//! cgroup component of the Linux process adapter.
//!
//! Extracted from `platform::linux_process` into a cohesive module; the
//! coordinator preserves the public `platform::linux_process` paths and
//! delegates to these items.  Bodies are behaviour-preserving moves.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Clone, Debug)]
pub(super) struct CgroupRoot {
    pub(super) path: PathBuf,
}

impl CgroupRoot {
    pub(super) fn open(path: &Path) -> Result<Self, AdapterError> {
        let metadata = fs::symlink_metadata(path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup root is unavailable: {error}"))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AdapterError::Unavailable(
                "cgroup root is not a directory".to_owned(),
            ));
        }
        let path = fs::canonicalize(path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup root cannot be canonicalized: {error}"))
        })?;
        for file in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            let control = path.join(file);
            let metadata = fs::symlink_metadata(&control).map_err(|error| {
                AdapterError::Unavailable(format!("required {file} is unavailable: {error}"))
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AdapterError::Unavailable(format!(
                    "required cgroup control {file} is not a regular control file"
                )));
            }
        }
        Ok(Self { path })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn create(&self, name: &str) -> Result<Cgroup, AdapterError> {
        validate_cgroup_name(name)?;
        let path = self.path.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(AdapterError::Unavailable(format!(
                "{CLEANUP_UNCERTAIN_MARKER}: requested cgroup containment {name} already exists; exact planned authority must be reconciled"
            )));
        }
        fs::create_dir(&path).map_err(|error| {
            AdapterError::Unavailable(format!("delegated cgroup creation failed: {error}"))
        })?;
        match Cgroup::existing(self, name) {
            Ok(cgroup) => Ok(cgroup),
            Err(error) => match fs::remove_dir(&path) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(AdapterError::Unavailable(format!(
                    "{CLEANUP_UNCERTAIN_MARKER}: cgroup {name} verification failed ({error}); planned containment remains retained because removal failed: {cleanup_error}"
                ))),
            },
        }
    }

    pub(super) fn maybe_existing(&self, name: &str) -> Result<Option<Cgroup>, AdapterError> {
        validate_cgroup_name(name)?;
        let path = self.path.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => Cgroup::existing(self, name).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(AdapterError::Unavailable(format!(
                "cannot inspect cgroup {name}: {error}"
            ))),
        }
    }

    pub(super) fn probe_delegation(&self) -> Result<(), AdapterError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let name = format!("ascension-probe-{}-{nonce}", std::process::id());
        let cgroup = self.create(&name)?;
        cgroup.remove()
    }
}

#[derive(Clone, Debug)]
pub(super) struct Cgroup {
    pub(super) name: String,
    pub(super) path: PathBuf,
}

impl Cgroup {
    pub(super) fn existing(root: &CgroupRoot, name: &str) -> Result<Self, AdapterError> {
        let path = root.path.join(name);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup {name} does not exist: {error}"))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AdapterError::Unavailable(format!(
                "cgroup {name} is not a trusted directory"
            )));
        }
        let canonical = fs::canonicalize(&path).map_err(|error| {
            AdapterError::Unavailable(format!("cgroup {name} cannot be canonicalized: {error}"))
        })?;
        if !canonical.starts_with(&root.path) || canonical != path {
            return Err(AdapterError::Unavailable(format!(
                "cgroup {name} escaped the delegated root"
            )));
        }
        for file in ["cgroup.procs", "cgroup.events", "cgroup.kill"] {
            let control = path.join(file);
            let metadata = fs::symlink_metadata(&control).map_err(|error| {
                AdapterError::Unavailable(format!("cgroup {name} lacks {file}: {error}"))
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(AdapterError::Unavailable(format!(
                    "cgroup {name} has invalid {file}"
                )));
            }
        }
        Ok(Self {
            name: name.to_owned(),
            path,
        })
    }

    pub(super) fn add_process(&self, pid: u32) -> Result<(), AdapterError> {
        if pid == 0 {
            return Err(AdapterError::Invalid("cannot assign pid zero".to_owned()));
        }
        self.write_control("cgroup.procs", &pid.to_string())
            .map_err(|error| {
                AdapterError::Unavailable(format!("cgroup assignment failed: {error}"))
            })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn pids(&self) -> Result<Vec<u32>, AdapterError> {
        let content = fs::read_to_string(self.path.join("cgroup.procs")).map_err(|error| {
            AdapterError::Unavailable(format!("cannot inspect cgroup {}: {error}", self.name))
        })?;
        let mut pids = Vec::new();
        for line in content.lines() {
            if pids.len() >= MAX_CGROUP_PIDS {
                return Err(AdapterError::Unavailable(
                    "cgroup process membership exceeds bounds".to_owned(),
                ));
            }
            let pid = line.trim().parse::<u32>().map_err(|_| {
                AdapterError::Unavailable(format!("cgroup {} contains an invalid pid", self.name))
            })?;
            if pid == 0 {
                return Err(AdapterError::Unavailable(
                    "cgroup process membership contains pid zero".to_owned(),
                ));
            }
            if !pids.contains(&pid) {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    pub(super) fn kill_all(&self) -> Result<(), AdapterError> {
        self.write_control("cgroup.kill", "1").map_err(|error| {
            AdapterError::Unavailable(format!("cgroup force cleanup failed: {error}"))
        })
    }

    pub(super) fn write_control(&self, file: &str, value: &str) -> std::io::Result<()> {
        let path = self.path.join(file);
        let mut handle = OpenOptions::new().write(true).open(path)?;
        handle.write_all(value.as_bytes())
    }

    pub(super) fn remove(&self) -> Result<(), AdapterError> {
        if !self.pids()?.is_empty() {
            return Err(AdapterError::Timeout(format!(
                "cgroup {} still contains processes",
                self.name
            )));
        }
        fs::remove_dir(&self.path).map_err(|error| {
            AdapterError::Io(format!("cannot remove empty cgroup {}: {error}", self.name))
        })?;
        Ok(())
    }
}

pub(super) fn make_containment_name(specification: &LaunchSpec) -> String {
    let mut hasher = Sha256::new();
    for value in [
        specification.deployment_id.as_bytes(),
        specification.instance_id.as_bytes(),
        specification.incarnation.as_bytes(),
        specification.launch_nonce.as_bytes(),
    ] {
        hasher.update(value);
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let suffix = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("ascension-{suffix}")
}

pub(super) fn containment_name(value: &str) -> Result<String, AdapterError> {
    let Some(name) = value.strip_prefix(CGROUP_PREFIX) else {
        return Err(AdapterError::Invalid(
            "process containment is not a Linux cgroup identity".to_owned(),
        ));
    };
    validate_cgroup_name(name)?;
    Ok(name.to_owned())
}

pub(super) fn validate_cgroup_name(name: &str) -> Result<(), AdapterError> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AdapterError::Invalid(
            "process containment name is outside bounds".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn discover_delegated_cgroup() -> Result<PathBuf, AdapterError> {
    let mountpoint = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| {
            AdapterError::Unavailable(format!("cgroup mountinfo unavailable: {error}"))
        })?
        .lines()
        .find_map(parse_cgroup2_mountpoint)
        .ok_or_else(|| AdapterError::Unavailable("no cgroup v2 mount is available".to_owned()))?;
    let relative = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| AdapterError::Unavailable(format!("process cgroup unavailable: {error}")))?
        .lines()
        .find_map(|line| line.strip_prefix("0::").map(str::to_owned))
        .ok_or_else(|| AdapterError::Unavailable("process has no cgroup v2 path".to_owned()))?;
    let relative = relative.trim_start_matches('/');
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(AdapterError::Unavailable(
            "process cgroup path is malformed".to_owned(),
        ));
    }
    let path = if relative.is_empty() {
        mountpoint
    } else {
        mountpoint.join(relative)
    };
    Ok(path)
}

pub(super) fn parse_cgroup2_mountpoint(line: &str) -> Option<PathBuf> {
    let mut sections = line.split(" - ");
    let pre = sections.next()?;
    let post = sections.next()?;
    if post
        .split_whitespace()
        .next()
        .is_none_or(|kind| kind != "cgroup2")
    {
        return None;
    }
    let fields = pre.split_whitespace().collect::<Vec<_>>();
    fields
        .get(4)
        .map(|field| PathBuf::from(unescape_mountinfo(field)))
}

pub(super) fn unescape_mountinfo(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}

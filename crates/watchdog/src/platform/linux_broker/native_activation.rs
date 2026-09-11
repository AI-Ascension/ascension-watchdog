//! Early, bounded intake. Names select descriptors; PID-1 inventory and durable
//! receipt validation establish authority later, before any descriptor is used.

use super::super::descriptor_store::DescriptorName;
use super::super::{BrokerError, BrokerResult, MAX_RECEIPTS, io_error};
use ascension_platform_linux_descriptors::{
    FIRST_ACTIVATION_FD, MAX_ACTIVATION_FDS, duplicate_activation_descriptor,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) type CapturedDescriptors = BTreeMap<DescriptorName, File>;
static CAPTURE_ATTEMPTED: AtomicBool = AtomicBool::new(false);

struct ActivationPlan {
    names: Vec<DescriptorName>,
    pidfd_id: Option<u64>,
}

pub(super) fn capture() -> BrokerResult<CapturedDescriptors> {
    if CAPTURE_ATTEMPTED.swap(true, Ordering::SeqCst) {
        return Err(BrokerError::Conflict(
            "activation intake may only run once in a broker process".to_owned(),
        ));
    }
    let pid = environment("LISTEN_PID", 10)?;
    let count = environment("LISTEN_FDS", 3)?;
    let names = environment("LISTEN_FDNAMES", MAX_RECEIPTS * 68)?;
    let pidfd_id = environment("LISTEN_PIDFDID", 20)?;
    let plan = parse(
        pid.as_deref(),
        count.as_deref(),
        names.as_deref(),
        pidfd_id.as_deref(),
        std::process::id(),
    )?;
    let pidfd_id = plan.pidfd_id;
    // Do not open any other files, including pidfds, before completing these
    // copies. The narrow FFI helper duplicates above the full activation range.
    let descriptors = copy_plan(plan, |descriptor| {
        duplicate_activation_descriptor(descriptor)
            .map(File::from)
            .map_err(io_error)
    })?;
    if let Some(expected) = pidfd_id {
        verify_pidfd_id(expected)?;
    }
    Ok(descriptors)
}

fn copy_plan<T>(
    plan: ActivationPlan,
    mut duplicate: impl FnMut(i32) -> BrokerResult<T>,
) -> BrokerResult<BTreeMap<DescriptorName, T>> {
    let mut descriptors = BTreeMap::new();
    for (index, name) in plan.names.into_iter().enumerate() {
        let descriptor = i32::try_from(index)
            .ok()
            .and_then(|index| FIRST_ACTIVATION_FD.checked_add(index))
            .ok_or_else(|| BrokerError::Invalid("activation descriptor overflows".to_owned()))?;
        descriptors.insert(name, duplicate(descriptor)?);
    }
    Ok(descriptors)
}

fn environment(name: &str, maximum: usize) -> BrokerResult<Option<String>> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    if value.len() > maximum {
        return Err(BrokerError::Invalid(
            "activation environment exceeds bound".to_owned(),
        ));
    }
    value
        .into_string()
        .map(Some)
        .map_err(|_| BrokerError::Invalid("activation environment is not UTF-8".to_owned()))
}

fn parse(
    pid: Option<&str>,
    count: Option<&str>,
    names: Option<&str>,
    pidfd_id: Option<&str>,
    own_pid: u32,
) -> BrokerResult<ActivationPlan> {
    if pid.is_none() && count.is_none() && names.is_none() && pidfd_id.is_none() {
        return Ok(ActivationPlan {
            names: Vec::new(),
            pidfd_id: None,
        });
    }
    if pid != Some(own_pid.to_string().as_str()) || own_pid == 0 {
        return Err(BrokerError::Unauthorized(
            "activation PID is not this broker".to_owned(),
        ));
    }
    let count = canonical_number(
        count.ok_or_else(|| BrokerError::Invalid("activation count is missing".to_owned()))?,
    )?;
    if count == 0 || count > MAX_RECEIPTS as u64 || count > MAX_ACTIVATION_FDS as u64 {
        return Err(BrokerError::Invalid(
            "activation count exceeds bound".to_owned(),
        ));
    }
    let names =
        names.ok_or_else(|| BrokerError::Invalid("activation names are missing".to_owned()))?;
    if names.len() > MAX_RECEIPTS * 68 {
        return Err(BrokerError::Invalid(
            "activation names exceed byte bound".to_owned(),
        ));
    }
    let mut parsed = Vec::new();
    let mut unique = BTreeSet::new();
    for name in names.split(':') {
        let name = DescriptorName::parse(name)?;
        if !unique.insert(name.clone()) || parsed.len() >= MAX_RECEIPTS {
            return Err(BrokerError::Conflict(
                "activation names are ambiguous".to_owned(),
            ));
        }
        parsed.push(name);
    }
    if parsed.len() as u64 != count {
        return Err(BrokerError::Conflict(
            "activation name count differs".to_owned(),
        ));
    }
    let pidfd_id = pidfd_id.map(canonical_number).transpose()?;
    if pidfd_id == Some(0) {
        return Err(BrokerError::Invalid(
            "activation pidfd identity is zero".to_owned(),
        ));
    }
    Ok(ActivationPlan {
        names: parsed,
        pidfd_id,
    })
}

fn canonical_number(value: &str) -> BrokerResult<u64> {
    let number = value
        .parse::<u64>()
        .map_err(|_| BrokerError::Invalid("activation integer is malformed".to_owned()))?;
    if value != number.to_string() {
        return Err(BrokerError::Invalid(
            "activation integer is not canonical".to_owned(),
        ));
    }
    Ok(number)
}

fn verify_pidfd_id(expected: u64) -> BrokerResult<()> {
    use rustix::fs::{fstat, fstatfs};
    use rustix::process::{Pid, PidfdFlags, pidfd_open};
    let pid = Pid::from_raw(
        std::process::id()
            .try_into()
            .map_err(|_| BrokerError::Unavailable("broker PID exceeds native range".to_owned()))?,
    )
    .ok_or_else(|| BrokerError::Unavailable("broker PID is zero".to_owned()))?;
    let descriptor =
        pidfd_open(pid, PidfdFlags::empty()).map_err(|error| io_error(error.into()))?;
    // systemd's 64-bit pidfd ID fallback requires pidfs (Linux >=6.9), not the
    // non-unique anon-inode pidfds of older kernels. 32-bit inode fallback is
    // deliberately unsupported; it cannot represent the complete ID.
    let filesystem = fstatfs(&descriptor).map_err(|error| io_error(error.into()))?;
    let metadata = fstat(&descriptor).map_err(|error| io_error(error.into()))?;
    if !cfg!(target_pointer_width = "64")
        || filesystem.f_type != 0x5049_4446
        || expected == 0
        || metadata.st_ino != expected
    {
        return Err(BrokerError::Unauthorized(
            "activation pidfd identity is not verified".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_later_copy_failure_drops_every_prior_owned_copy() -> BrokerResult<()> {
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;
        struct DropWitness(Arc<AtomicUsize>);
        impl Drop for DropWitness {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let names = format!("cg-{}:cg-{}", "a".repeat(64), "b".repeat(64));
        let plan = parse(Some("42"), Some("2"), Some(&names), None, 42)?;
        let mut slots = Vec::new();
        let result = copy_plan(plan, |descriptor| {
            slots.push(descriptor);
            if descriptor == FIRST_ACTIVATION_FD {
                Ok(DropWitness(Arc::clone(&dropped)))
            } else {
                Err(BrokerError::Io("injected descriptor exhaustion".to_owned()))
            }
        });
        assert!(result.is_err());
        assert_eq!(slots, vec![3, 4]);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[test]
    fn first_start_and_exact_current_pid_named_activation_are_distinct() -> BrokerResult<()> {
        assert!(parse(None, None, None, None, 42)?.names.is_empty());
        let name = format!("cg-{}", "a".repeat(64));
        let plan = parse(Some("42"), Some("1"), Some(&name), Some("1234"), 42)?;
        assert_eq!(plan.names.len(), 1);
        assert_eq!(plan.pidfd_id, Some(1234));
        Ok(())
    }

    #[test]
    fn malformed_or_partial_activation_cannot_claim_descriptors() {
        let name = format!("cg-{}", "a".repeat(64));
        for (pid, count, names, pidfd) in [
            (None, Some("1"), Some(name.as_str()), None),
            (Some("41"), Some("1"), Some(name.as_str()), None),
            (Some("042"), Some("1"), Some(name.as_str()), None),
            (Some("42"), None, Some(name.as_str()), None),
            (Some("42"), Some("0"), Some(""), None),
            (Some("42"), Some("129"), Some(name.as_str()), None),
            (Some("42"), Some("01"), Some(name.as_str()), None),
            (Some("42"), Some("1"), None, None),
            (Some("42"), Some("1"), Some("unknown"), None),
            (Some("42"), Some("2"), Some(name.as_str()), None),
            (Some("42"), Some("1"), Some(name.as_str()), Some("+123")),
            (Some("42"), Some("1"), Some(name.as_str()), Some("001")),
            (Some("42"), Some("1"), Some(name.as_str()), Some("0")),
        ] {
            assert!(parse(pid, count, names, pidfd, 42).is_err());
        }
        let duplicate = format!("{name}:{name}");
        assert!(parse(Some("42"), Some("2"), Some(&duplicate), None, 42).is_err());
    }
}

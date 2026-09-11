// SPDX-License-Identifier: MIT

//! Owner-local immutable images and watchdog configuration for the real smoke.

use super::real_harness_worker_gateway::GatewayFixture;
use ascension_watchdog::config::{
    ComponentConfig, DesiredMode, WatchdogConfig, WorkerConfig, hex_digest, validate_digest,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use tempfile::TempDir;

const HARNESS_BINARY_ENV: &str = "STS2_HARNESS_RUNTIME_BINARY";
const HARNESS_SHA256_ENV: &str = "STS2_HARNESS_RUNTIME_SHA256";
const REVIEWED_EXO_REVISION: &str = "7801005e6a1ab77008a05dbba80e0a2a7a56e35d";
const WORKER_PROFILE_DIGEST: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
const STATE_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PROVIDER_DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const WORKER_TIMEOUT_MS: u64 = 5_000;
const RUNTIME_SETTLEMENT_TIMEOUT_SECONDS: u64 = 30;
const MAX_EXECUTABLE_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Debug)]
struct ApprovedHarness {
    source: PathBuf,
    sha256: String,
}

impl ApprovedHarness {
    fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
        let source = required_path(HARNESS_BINARY_ENV)?;
        if !source.is_absolute()
            || source
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || source.as_os_str().is_empty()
        {
            return Err(io::Error::other(format!(
                "{HARNESS_BINARY_ENV} must be an absolute path without traversal"
            ))
            .into());
        }
        reject_shared_or_pseudo_path(&source, HARNESS_BINARY_ENV)?;
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(io::Error::other(format!(
                "{HARNESS_BINARY_ENV} must name a regular non-symlink file"
            ))
            .into());
        }
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(
                io::Error::other(format!("{HARNESS_BINARY_ENV} must be executable")).into(),
            );
        }
        let canonical = fs::canonicalize(&source)?;
        if canonical != source {
            return Err(io::Error::other(format!(
                "{HARNESS_BINARY_ENV} must already be canonical"
            ))
            .into());
        }
        let expected = required_text(HARNESS_SHA256_ENV)?;
        validate_digest(&expected).map_err(io::Error::other)?;
        let (actual, _) = hash_regular_file(&source)?;
        if actual != expected {
            return Err(io::Error::other(format!(
                "{HARNESS_BINARY_ENV} digest differs from {HARNESS_SHA256_ENV}"
            ))
            .into());
        }
        Ok(Self {
            source,
            sha256: expected,
        })
    }
}

pub(super) struct Fixture {
    temp: Option<TempDir>,
    _gateway: GatewayFixture,
    config_path: PathBuf,
    daemon_image: PathBuf,
    cleanup_verified: bool,
}

impl Fixture {
    pub(super) fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
        Self::new(&ApprovedHarness::from_environment()?)
    }

    pub(super) fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub(super) fn daemon_image(&self) -> &Path {
        &self.daemon_image
    }

    pub(super) fn mark_cleanup_verified(&mut self) {
        self.cleanup_verified = true;
    }

    fn new(approved: &ApprovedHarness) -> Result<Self, Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700))?;
        let gateway = GatewayFixture::new()?;
        let gateway_address = gateway.address().to_owned();
        let daemon_image = temp.path().join("watchdog");
        // A native test launched from a separately provisioned guest cannot
        // resolve the build-host path embedded by Cargo.  Keep Cargo's path
        // as the default for ordinary runs, while allowing the operator to
        // pin the exact staged watchdog image explicitly for that guest.
        let daemon_source = std::env::var_os("ASCENSION_WATCHDOG_EXECUTABLE").map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_watchdog")),
            PathBuf::from,
        );
        copy_immutable_image(
            &daemon_source,
            &daemon_image,
            &hash_regular_file(&daemon_source)?.0,
        )?;
        let worker_namespace = temp.path().join("worker");
        fs::create_dir(&worker_namespace)?;
        fs::set_permissions(&worker_namespace, fs::Permissions::from_mode(0o700))?;

        let harness_image = temp.path().join("sts2-harness-runtime");
        copy_immutable_image(&approved.source, &harness_image, &approved.sha256)?;
        let mcp_image = temp.path().join("mcp-fixture");
        copy_immutable_image(
            Path::new("/usr/bin/true"),
            &mcp_image,
            &hash_regular_file(Path::new("/usr/bin/true"))?.0,
        )?;

        let credential_path = temp.path().join("worker.credential");
        fs::write(&credential_path, b"real-harness-worker-credential")?;
        fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600))?;

        let namespace = worker_namespace
            .to_str()
            .ok_or_else(|| io::Error::other("worker namespace is not UTF-8"))?;
        let mcp = mcp_image
            .to_str()
            .ok_or_else(|| io::Error::other("MCP fixture path is not UTF-8"))?;
        let runtime_digest = runtime_config_digest(mcp, &gateway_address)?;
        let mut environment = worker_environment(
            namespace,
            &credential_path,
            &mcp_image,
            &temp.path().join("harness-execution.sqlite3"),
            &runtime_digest,
            &approved.sha256,
            &gateway_address,
        )?;
        let runtime = harness_image
            .to_str()
            .ok_or_else(|| io::Error::other("worker runtime path is not UTF-8"))?;
        environment.insert("STS2_WORKER_RUNTIME_BINARY".to_owned(), runtime.to_owned());
        environment.insert(
            "STS2_WORKER_RUNTIME_SHA256".to_owned(),
            approved.sha256.clone(),
        );
        let config = WatchdogConfig {
            deployment_id: "watchdog-real-harness-smoke".to_owned(),
            database: temp.path().join("watchdog.sqlite3"),
            desired_mode: DesiredMode::Running,
            probe_interval_ms: 2_000,
            restart_budget_count: 1,
            components: vec![ComponentConfig {
                id: "harness".to_owned(),
                executable: harness_image.clone(),
                args: Vec::new(),
                cwd: Some(temp.path().to_path_buf()),
                environment,
                executable_sha256: Some(approved.sha256.clone()),
                restart: true,
            }],
            worker: Some(WorkerConfig {
                component_id: "harness".to_owned(),
                endpoint_namespace: worker_namespace,
                credential_path,
                allowed_peer_sid: None,
                worker_profile_digest: WORKER_PROFILE_DIGEST.to_owned(),
                release_digest: approved.sha256.clone(),
                worker_config_digest: runtime_digest,
                schema_digest: ascension_watchdog::storage::WORKER_HANDOFF_SCHEMA_DIGEST.to_owned(),
                timeout_ms: WORKER_TIMEOUT_MS,
            }),
            ..WatchdogConfig::default()
        };
        config.validate()?;
        let config_path = temp.path().join("watchdog.json");
        config.to_file(&config_path)?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
        Ok(Self {
            temp: Some(temp),
            _gateway: gateway,
            config_path,
            daemon_image,
            cleanup_verified: false,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Preserve durable stop/identity evidence on every failed native run,
        // including any bounded cleanup uncertainty reported by DaemonGuard.
        if !self.cleanup_verified
            && let Some(temp) = self.temp.take()
        {
            eprintln!(
                "native worker fixture retained at {}",
                temp.keep().display()
            );
        }
    }
}

fn worker_environment(
    namespace: &str,
    credential_path: &Path,
    mcp_path: &Path,
    execution_store: &Path,
    runtime_digest: &str,
    harness_sha256: &str,
    gateway_address: &str,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let mcp = mcp_path
        .to_str()
        .ok_or_else(|| io::Error::other("MCP path is not UTF-8"))?;
    let credential = credential_path
        .to_str()
        .ok_or_else(|| io::Error::other("worker credential path is not UTF-8"))?;
    let store = execution_store
        .to_str()
        .ok_or_else(|| io::Error::other("execution store path is not UTF-8"))?;
    let values = [
        ("STS2_WORKER_MODE", "true".to_owned()),
        ("STS2_RUNTIME_PROFILE", "runtime-v3-gameplay".to_owned()),
        ("STS2_GATEWAY_ADDR", gateway_address.to_owned()),
        ("STS2_GATEWAY_TOKEN", "unused-gateway-token".to_owned()),
        ("STS2_MCP_BINARY", mcp.to_owned()),
        ("STS2_INSTANCE_ID", "instance-real-harness-smoke".to_owned()),
        ("STS2_CALLER_ID", "caller-real-harness-smoke".to_owned()),
        ("STS2_SESSION_ID", "session-real-harness-smoke".to_owned()),
        ("STS2_LEASE_ID", "lease-real-harness-smoke".to_owned()),
        ("STS2_LEASE_EPOCH", "1".to_owned()),
        (
            "STS2_MCP_SESSION_ID",
            "mcp-session-real-harness-smoke".to_owned(),
        ),
        ("STS2_RUN_ID", "run-real-harness-smoke".to_owned()),
        ("STS2_EPISODE_ID", "episode-real-harness-smoke".to_owned()),
        (
            "STS2_TRAJECTORY_ID",
            "trajectory-real-harness-smoke".to_owned(),
        ),
        ("STS2_TRACE_ID", "trace-real-harness-smoke".to_owned()),
        ("STS2_ARTIFACT_ID", "artifact-real-harness-smoke".to_owned()),
        (
            "STS2_RUNTIME_SETTLEMENT_TIMEOUT_SECONDS",
            RUNTIME_SETTLEMENT_TIMEOUT_SECONDS.to_string(),
        ),
        (
            "STS2_WORKER_DEPLOYMENT_ID",
            "watchdog-real-harness-smoke".to_owned(),
        ),
        (
            "STS2_WORKER_PROFILE_DIGEST",
            WORKER_PROFILE_DIGEST.to_owned(),
        ),
        ("STS2_BUILD_DIGEST", harness_sha256.to_owned()),
        ("STS2_STATE_DIGEST", STATE_DIGEST.to_owned()),
        ("STS2_PROVIDER_DIGEST", PROVIDER_DIGEST.to_owned()),
        ("STS2_RUNTIME_CONFIG_DIGEST", runtime_digest.to_owned()),
        ("STS2_SEED", "seed-real-harness-smoke".to_owned()),
        ("STS2_WORKER_ENDPOINT_NAMESPACE", namespace.to_owned()),
        ("STS2_WORKER_CREDENTIAL_PATH", credential.to_owned()),
        ("STS2_WORKER_TIMEOUT_MS", WORKER_TIMEOUT_MS.to_string()),
        ("STS2_EXECUTION_STORE_PATH", store.to_owned()),
        ("STS2_EXO_BRIDGE_BINARY", "/bin/true".to_owned()),
        ("STS2_EXO_REVISION", REVIEWED_EXO_REVISION.to_owned()),
        ("STS2_EXO_FORWARD_VISIBLE_SEED", "true".to_owned()),
        (
            "STS2_OBJECTIVE",
            "real watchdog harness worker smoke".to_owned(),
        ),
        ("STS2_MAX_STEPS", "1".to_owned()),
    ];
    let mut environment = BTreeMap::new();
    for (key, value) in values {
        environment.insert(key.to_owned(), value);
    }
    Ok(environment)
}

fn runtime_config_digest(
    mcp_path: &str,
    gateway_address: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let mcp = Path::new(mcp_path);
    let (mcp_sha256, mcp_bytes) = hash_regular_file(mcp)?;
    let value = json!({
        "runtime_profile": "runtime-v3-gameplay",
        "gateway_address": gateway_address,
        "mcp_binary": mcp_path,
        "mcp_executable": {
            "path": mcp_path,
            "sha256": mcp_sha256,
            "bytes": mcp_bytes,
        },
        "instance_id": "instance-real-harness-smoke",
        "caller_id": "caller-real-harness-smoke",
        "session_id": "session-real-harness-smoke",
        "lease_id": "lease-real-harness-smoke",
        "lease_epoch": 1,
        "mcp_session_id": "mcp-session-real-harness-smoke",
        "run_id": "run-real-harness-smoke",
        "episode_id": "episode-real-harness-smoke",
        "trajectory_id": "trajectory-real-harness-smoke",
        "trace_id": "trace-real-harness-smoke",
        "artifact_id": "artifact-real-harness-smoke",
        "settlement_timeout_seconds": RUNTIME_SETTLEMENT_TIMEOUT_SECONDS,
        "exo_revision": REVIEWED_EXO_REVISION,
        "exo_max_request_bytes": 131_072,
        "exo_max_response_bytes": 8_192,
        "exo_timeout_millis": 120_000,
        "exo_forward_visible_seed": true,
        "exo_bridge": {
            "executable": "/bin/true",
            "arguments": [],
            "working_directory": Value::Null,
            "inherited_environment": [],
        },
        "runner": {
            "max_steps": 1,
            "objective": "real watchdog harness worker smoke",
            "hard_constraints": [],
        },
    });
    let bytes = serde_json::to_vec(&value)?;
    Ok(hex_digest(&bytes))
}

fn copy_immutable_image(
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::copy(source, destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o500))?;
    let metadata = fs::symlink_metadata(destination)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::other(format!(
            "staged image {} is not a regular file",
            destination.display()
        ))
        .into());
    }
    let (actual, _) = hash_regular_file(destination)?;
    if actual != expected_sha256 {
        return Err(io::Error::other(format!(
            "staged image {} changed while copied",
            destination.display()
        ))
        .into());
    }
    Ok(())
}

fn hash_regular_file(path: &Path) -> Result<(String, u64), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::other(format!(
            "{} must be a regular non-symlink file",
            path.display()
        ))
        .into());
    }
    if metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(io::Error::other(format!(
            "{} exceeds the bounded executable size",
            path.display()
        ))
        .into());
    }
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 32 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read)?)
            .ok_or_else(|| io::Error::other("executable byte count overflowed"))?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(io::Error::other("executable exceeded its bounded size").into());
        }
        digest.update(&buffer[..read]);
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut encoded, "{byte:02x}")?;
    }
    Ok((encoded, total))
}

#[test]
fn streaming_image_digest_matches_standard_sha256() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("digest-fixture");
    fs::write(&path, b"abc")?;
    let (digest, bytes) = hash_regular_file(&path)?;
    assert_eq!(bytes, 3);
    assert_eq!(
        digest,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    Ok(())
}

fn required_text(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    match std::env::var(name) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(io::Error::other(format!("{name} must not be empty")).into()),
        Err(std::env::VarError::NotPresent) => {
            Err(io::Error::other(format!("{name} is required")).into())
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(io::Error::other(format!("{name} is not valid UTF-8")).into())
        }
    }
}

fn required_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let value =
        std::env::var_os(name).ok_or_else(|| io::Error::other(format!("{name} is required")))?;
    if value.is_empty() {
        return Err(io::Error::other(format!("{name} must not be empty")).into());
    }
    Ok(PathBuf::from(value))
}

fn reject_shared_or_pseudo_path(path: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if normalized == "/mnt"
        || normalized.starts_with("/mnt/")
        || normalized == "/proc"
        || normalized.starts_with("/proc/")
        || normalized == "/sys"
        || normalized.starts_with("/sys/")
        || normalized == "/dev"
        || normalized.starts_with("/dev/")
        || normalized.starts_with("//wsl")
    {
        return Err(
            io::Error::other(format!("{name} must remain on an owner-local filesystem")).into(),
        );
    }
    Ok(())
}

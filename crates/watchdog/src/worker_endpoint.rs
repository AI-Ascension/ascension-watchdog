//! Pure launch-specific endpoint selection; no filesystem or IPC effects.

use crate::error::{Result, WatchdogError};

pub const WINDOWS_NAMESPACE: &str = r"\\.\pipe\ascension-worker-";

#[derive(Clone, Copy, Debug)]
pub enum EndpointPlatform {
    Linux,
    Windows,
}

/// Resolve approved static namespace policy using the owned launch identity.
/// A namespace is not an existing endpoint and never authorizes unlinking one.
pub fn resolve(platform: EndpointPlatform, namespace: &str, nonce: &str) -> Result<String> {
    let id = uuid::Uuid::parse_str(nonce).map_err(|_| invalid())?;
    if id.get_version_num() != 4
        || id.get_variant() != uuid::Variant::RFC4122
        || id.to_string() != nonce
    {
        return Err(invalid());
    }
    match platform {
        EndpointPlatform::Windows => {
            if namespace != WINDOWS_NAMESPACE {
                return Err(invalid());
            }
            Ok(format!("{namespace}{nonce}"))
        }
        EndpointPlatform::Linux => {
            if namespace.len() > 100
                || !namespace.starts_with('/')
                || namespace.contains('\\')
                || namespace.chars().any(char::is_control)
                || namespace[1..]
                    .split('/')
                    .any(|part| matches!(part, "" | "." | ".."))
            {
                return Err(invalid());
            }
            let endpoint = format!("{namespace}/ascension-worker-{nonce}.sock");
            if endpoint.len() > 100 {
                return Err(invalid());
            }
            Ok(endpoint)
        }
    }
}

fn invalid() -> WatchdogError {
    WatchdogError::InvalidInput("invalid worker endpoint namespace or launch nonce".to_owned())
}

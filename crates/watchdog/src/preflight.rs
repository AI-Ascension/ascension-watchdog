// SPDX-License-Identifier: MIT
//! Read-only disk headroom admission. A successful probe is a point-in-time
//! observation, not a reservation or a durability/host-authorization guarantee.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Explicit capacity allowances for one bounded operation. Staging, backup and
/// runtime reserves must coexist; none is reclaimed implicitly by this check.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiskRequirements {
    pub runtime_reserve_bytes: u64,
    pub staging_bytes: u64,
    pub backup_bytes: u64,
}

/// Bounded diagnostic data, deliberately excluding host paths and identifiers.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct DiskInspection {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub required_bytes: u64,
    pub admitted: bool,
}

impl DiskRequirements {
    /// Evaluate capacity sampled by a platform adapter without changing it.
    ///
    /// # Errors
    /// Rejects an absent runtime reserve, impossible capacity or arithmetic
    /// overflow. Insufficient space is a valid, non-admitted inspection.
    pub fn evaluate(
        self,
        total_bytes: u64,
        available_bytes: u64,
    ) -> Result<DiskInspection, String> {
        if self.runtime_reserve_bytes == 0 || total_bytes == 0 || available_bytes > total_bytes {
            return Err("invalid disk capacity or runtime reserve".to_owned());
        }
        let required_bytes = self
            .runtime_reserve_bytes
            .checked_add(self.staging_bytes)
            .and_then(|sum| sum.checked_add(self.backup_bytes))
            .ok_or_else(|| "disk capacity requirement overflow".to_owned())?;
        Ok(DiskInspection {
            total_bytes,
            available_bytes,
            required_bytes,
            admitted: available_bytes >= required_bytes,
        })
    }

    /// Inspect an existing local state directory without creating files,
    /// initializing databases, deleting logs or reserving disk space.
    ///
    /// # Errors
    /// Rejects indirect/non-directory roots, filesystem query failures and
    /// invalid requirements. Local-filesystem suitability and ACL checks remain
    /// separate platform gates; free space alone does not establish either.
    pub fn inspect(self, directory: &Path) -> Result<DiskInspection, String> {
        crate::release::require_real_root(directory)?;
        let total = fs2::total_space(directory)
            .map_err(|error| format!("disk total capacity unavailable: {error}"))?;
        let available = fs2::available_space(directory)
            .map_err(|error| format!("disk available capacity unavailable: {error}"))?;
        self.evaluate(total, available)
    }
}

//! Durable, atomic writes of the scope ownership proof.

use super::properties::{ScopeProof, validate_scope_proof};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

pub(crate) fn write_proof(
    path: &Path,
    proof: &ScopeProof,
) -> Result<(), Box<dyn std::error::Error>> {
    validate_scope_proof(proof).map_err(io::Error::other)?;
    let bytes = serde_json::to_vec_pretty(proof)?;
    let temporary = path.with_extension(format!("proof.json.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    if let Some(parent) = path.parent() {
        let directory = File::open(parent)?;
        directory.sync_all()?;
    }
    Ok(())
}

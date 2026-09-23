//! Deterministic bundle synchronization and pinned source verification.

use crate::Result;
use crate::cli::Cli;
use crate::digest::sha256_hex;
use crate::identifiers::{is_upper_identifier, valid_commit, valid_profile_id, valid_repository};
use crate::model::{LockEntry, LockFile, LockSource};
use crate::paths::{
    collect_files, copy_if_absent_or_equal, inspect_managed_destination, prepare_managed_path,
    require_directory,
};
use crate::planning::generated_profile;
use crate::validate::{
    validate_adoption_identity, validate_conformance_inventory, validate_lock_shape,
    validate_profile, validate_profile_catalog, validate_repository_map, validate_rules,
    validate_schemas,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn sync_bundle(args: &Cli) -> Result<()> {
    let source_root = args.source_root.canonicalize().map_err(|error| {
        format!(
            "cannot read source root {}: {error}",
            args.source_root.display()
        )
    })?;
    let target_root = if args.target_root.as_os_str().is_empty() {
        return Err("--target-root is required for sync".to_owned());
    } else {
        args.target_root.clone()
    };
    if !valid_repository(&args.repository)
        || !valid_profile_id(&args.profile_id)
        || !is_upper_identifier(&args.owner)
        || !valid_commit(&args.source_commit)
    {
        return Err("sync repository, profile, owner, or source commit is invalid".to_owned());
    }
    let source_standards = source_root.join("standards");
    require_directory(&source_standards)?;
    let profile_ids = validate_profile_catalog(&source_standards.join("profiles.yaml"))?;
    validate_repository_map(&source_standards.join("repositories.yaml"), &profile_ids)?;
    validate_rules(&source_standards.join("rules.yaml"))?;
    validate_schemas(&source_standards.join("schemas"))?;
    validate_conformance_inventory(&source_standards.join("conformance"))?;
    validate_adoption_identity(
        &source_standards.join("repositories.yaml"),
        &args.repository,
        &args.owner,
        &args.profile_id,
    )?;

    let target_root = if target_root.exists() {
        require_directory(&target_root)?;
        target_root
            .canonicalize()
            .map_err(|error| format!("cannot read target root: {error}"))?
    } else {
        fs::create_dir_all(&target_root)
            .map_err(|error| format!("cannot create target root: {error}"))?;
        target_root
            .canonicalize()
            .map_err(|error| format!("cannot resolve target root: {error}"))?
    };
    if source_root == target_root {
        return Err("source and target roots must differ".to_owned());
    }

    let mut files = Vec::new();
    collect_files(&source_standards, &source_standards, &mut files)?;
    files.sort();
    let mut entries = Vec::new();
    let mut source_bytes = Vec::new();
    let mut bundle_input = Vec::new();
    for path in files {
        let source_path = source_root.join(&path);
        let bytes = fs::read(&source_path)
            .map_err(|error| format!("cannot read {}: {error}", source_path.display()))?;
        append_bundle_record(&mut bundle_input, &path, &bytes);
        entries.push(LockEntry {
            path: path.clone(),
            sha256: sha256_hex(&bytes),
        });
        source_bytes.push((path, bytes));
    }
    verify_source_commit_content(&source_root, &args.source_commit, &source_bytes)?;
    let bundle_digest = format!("sha256:{}", sha256_hex(&bundle_input));
    let profile = generated_profile(
        &args.profile_id,
        &args.repository,
        &args.owner,
        &args.source_commit,
        &bundle_digest,
    )?;
    let profile_text = toml::to_string_pretty(&profile)
        .map_err(|error| format!("cannot encode profile: {error}"))?;
    let lock = LockFile {
        profile_sha256: sha256_hex(profile_text.as_bytes()),
        lock_version: 1,
        repository: args.repository.clone(),
        profile_id: args.profile_id.clone(),
        source: LockSource {
            repository: "AI-Ascension/.github".to_owned(),
            commit: args.source_commit.clone(),
            bundle_digest: bundle_digest.clone(),
            distribution: "local".to_owned(),
            published: false,
        },
        files: entries,
        protected_paths: vec![
            "standards/schemas".to_owned(),
            "standards/conformance".to_owned(),
        ],
        generated_by: "standards-sync/1".to_owned(),
    };
    validate_profile(&profile)?;
    validate_lock_shape(&lock, &profile)?;
    let lock_text = serde_json::to_string_pretty(&lock)
        .map_err(|error| format!("cannot encode lock: {error}"))?
        + "\n";

    // Detect a conflict anywhere in the managed set before writing its first file.
    // This protects a developer's existing copy even when the conflicting entry
    // sorts after many new bundle files.
    for (path, bytes) in &source_bytes {
        inspect_managed_destination(&target_root, path, bytes)?;
    }
    inspect_managed_destination(
        &target_root,
        "standards-profile.toml",
        profile_text.as_bytes(),
    )?;
    inspect_managed_destination(&target_root, "standards.lock.json", lock_text.as_bytes())?;

    for (path, bytes) in source_bytes {
        let target_path = prepare_managed_path(&target_root, &path)?;
        copy_if_absent_or_equal(&target_path, &bytes)?;
    }
    let profile_path = prepare_managed_path(&target_root, "standards-profile.toml")?;
    copy_if_absent_or_equal(&profile_path, profile_text.as_bytes())?;
    let lock_path = prepare_managed_path(&target_root, "standards.lock.json")?;
    copy_if_absent_or_equal(&lock_path, lock_text.as_bytes())?;
    println!(
        "synced {} files to {} bundle_digest={bundle_digest} published=false",
        lock.files.len(),
        target_root.display()
    );
    Ok(())
}

pub(crate) fn verify_source_commit_content(
    source_root: &Path,
    commit: &str,
    source_bytes: &[(String, Vec<u8>)],
) -> Result<()> {
    let top_level = git_output(
        source_root,
        &["rev-parse".to_owned(), "--show-toplevel".to_owned()],
    )?;
    let top_level = String::from_utf8(top_level)
        .map_err(|error| format!("git returned a non-UTF-8 repository path: {error}"))?;
    let top_level = PathBuf::from(top_level.trim());
    if top_level != source_root {
        return Err(format!(
            "source root {} is not the Git worktree root {}",
            source_root.display(),
            top_level.display()
        ));
    }
    git_output(
        source_root,
        &[
            "cat-file".to_owned(),
            "-e".to_owned(),
            format!("{commit}^{{commit}}"),
        ],
    )?;
    let tree = git_output(
        source_root,
        &[
            "ls-tree".to_owned(),
            "-r".to_owned(),
            "--name-only".to_owned(),
            commit.to_owned(),
            "--".to_owned(),
            "standards".to_owned(),
        ],
    )?;
    let mut committed = String::from_utf8(tree)
        .map_err(|error| format!("source commit tree is not UTF-8: {error}"))?
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    committed.sort();
    let mut expected = source_bytes
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    expected.sort();
    if committed != expected {
        return Err(
            "source commit standards tree differs from the source checkout inventory; commit the exact source bundle first"
                .to_owned(),
        );
    }
    for (path, expected_bytes) in source_bytes {
        let object = format!("{commit}:{path}");
        let actual = git_output(source_root, &["show".to_owned(), object])?;
        if &actual != expected_bytes {
            return Err(format!(
                "source commit content differs from checkout for {path}; refusing sync"
            ));
        }
    }
    Ok(())
}

pub(crate) fn git_output(root: &Path, args: &[String]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|error| format!("cannot execute git for {}: {error}", root.display()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        return Err(format!(
            "git {} failed{}",
            args.join(" "),
            if detail.is_empty() {
                String::new()
            } else {
                format!(": {detail}")
            }
        ));
    }
    Ok(output.stdout)
}

pub(crate) fn append_bundle_record(input: &mut Vec<u8>, path: &str, bytes: &[u8]) {
    input.extend_from_slice(path.as_bytes());
    input.push(0);
    input.extend_from_slice(bytes);
    input.push(0);
}

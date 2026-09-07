use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

pub(super) struct Fixture(pub(super) PathBuf);

impl Fixture {
    pub(super) fn new() -> Result<Self> {
        create_fixture_directory().map(Self)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only remove the directory this test successfully reserved itself.
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn canonical_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn canonical_profile() -> Result<Profile> {
    generated_profile(
        "org-governance",
        "AI-Ascension/.github",
        "ORG",
        "0123456789abcdef0123456789abcdef01234567",
        &format!("sha256:{}", "0".repeat(64)),
    )
}

#[test]
fn missing_target_directory_fails_even_when_other_targets_exist() -> TestResult {
    let fixture = Fixture::new()?;
    let mut profile = canonical_profile()?;
    validate_check_targets(&fixture.0, &profile.checks)?;
    let check = profile
        .checks
        .commands
        .get_mut("link-check")
        .ok_or("missing fixture check")?;
    check.target = "missing/target".to_owned();
    assert!(validate_check_targets(&fixture.0, &profile.checks).is_err());
    fs::create_dir_all(fixture.0.join("missing/target"))?;
    validate_check_targets(&fixture.0, &profile.checks)?;
    Ok(())
}

#[test]
fn mandatory_check_removal_replacement_and_demotion_fail() -> TestResult {
    let profile = canonical_profile()?;
    validate_required_checks(&profile)?;
    let mut removed = profile.clone();
    removed.checks.commands.remove("standards-conformance");
    removed.checks.required.clear();
    assert!(validate_required_checks(&removed).is_err());
    let mut replaced = profile.clone();
    replaced
        .checks
        .commands
        .get_mut("standards-conformance")
        .ok_or("missing fixture check")?
        .command = "echo success".to_owned();
    assert!(validate_required_checks(&replaced).is_err());
    let mut demoted = profile.clone();
    demoted.checks.extended.append(&mut demoted.checks.required);
    assert!(validate_required_checks(&demoted).is_err());
    let mut no_scope = profile.clone();
    no_scope.scopes.clear();
    assert!(validate_required_checks(&no_scope).is_err());
    let mut no_checks = profile;
    no_checks.checks.fast.clear();
    no_checks.checks.required.clear();
    no_checks.checks.extended.clear();
    no_checks.checks.commands.clear();
    assert!(validate_check_sets(&no_checks.checks).is_err());
    Ok(())
}

#[test]
fn identity_must_match_the_reviewed_repository_map() -> TestResult {
    let map = canonical_root().join("standards/repositories.yaml");
    validate_adoption_identity(&map, "AI-Ascension/sts2-protocol", "PROTO", "rust-pure")?;
    assert!(
        validate_adoption_identity(&map, "AI-Ascension/sts2-protocol", "ORG", "rust-pure").is_err()
    );
    assert!(
        validate_adoption_identity(&map, "AI-Ascension/sts2-protocol", "PROTO", "web-php").is_err()
    );
    assert!(validate_adoption_identity(&map, "AI-Ascension/unknown", "ORG", "rust-pure").is_err());
    assert!(
        validate_adoption_identity(
            &map,
            "AI-Ascension/ascension-brand-overhaul",
            "ORG",
            "brand-package"
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn only_the_tools_exact_cargo_output_directory_is_ignored() -> TestResult {
    let fixture = Fixture::new()?;
    fs::create_dir_all(fixture.0.join("tools/standards-sync/target"))?;
    fs::write(
        fixture.0.join("tools/standards-sync/target/output"),
        "compiler output",
    )?;
    fs::create_dir_all(fixture.0.join("schemas/target"))?;
    fs::write(fixture.0.join("schemas/target/data.json"), "{}")?;
    let mut files = Vec::new();
    collect_files(&fixture.0, &fixture.0, &mut files)?;
    assert_eq!(files, ["standards/schemas/target/data.json"]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn linked_directories_and_broken_links_are_not_exempt_outputs() -> TestResult {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new()?;
    let other = Fixture::new()?;
    let mut profile = canonical_profile()?;
    symlink(&other.0, fixture.0.join("linked"))?;
    profile
        .checks
        .commands
        .get_mut("link-check")
        .ok_or("missing fixture check")?
        .target = "linked/child".to_owned();
    fs::create_dir(other.0.join("child"))?;
    assert!(validate_check_targets(&fixture.0, &profile.checks).is_err());
    assert!(inspect_managed_destination(&fixture.0, "linked/source", b"fixture").is_err());
    fs::remove_file(fixture.0.join("linked"))?;
    fs::create_dir_all(fixture.0.join("tools/standards-sync"))?;
    symlink(
        other.0.join("missing"),
        fixture.0.join("tools/standards-sync/target"),
    )?;
    assert!(collect_files(&fixture.0, &fixture.0, &mut Vec::new()).is_err());
    Ok(())
}

#[test]
fn expired_future_and_unverified_approvals_cannot_suppress_a_rule() -> TestResult {
    let path = canonical_root().join("standards/conformance/valid-exception.yaml");
    let mut exception: Exception = parse_yaml(&path)?;
    let date = date_days(FIXTURE_AS_OF)?;
    validate_exception(&exception, None, date, true)?;
    assert!(validate_exception(&exception, None, date, false).is_err());
    exception.approval.record = "https://github.com/AI-Ascension/.github/pull/1".to_owned();
    assert!(validate_exception(&exception, None, date, false).is_err());
    exception.approval.record = "local-review:fixture-review".to_owned();
    assert!(validate_exception(&exception, None, date_days("2026-10-08")?, true).is_err());
    assert!(validate_exception(&exception, None, date_days("2026-09-06")?, true).is_err());
    let rules = BTreeMap::from([("X-ERR-001".to_owned(), false)]);
    assert!(validate_exception(&exception, Some(&rules), date, true).is_err());
    exception.paths = vec!["src/../outside".to_owned()];
    assert!(validate_exception(&exception, None, date, true).is_err());
    Ok(())
}

fn copy_canonical_bundle(destination: &Path) -> Result<()> {
    let source = canonical_root();
    let directory = source.join("standards");
    let mut files = Vec::new();
    collect_files(&directory, &directory, &mut files)?;
    for relative in files {
        let target = prepare_managed_path(destination, &relative)?;
        fs::copy(source.join(relative), target).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn commit_bundle(root: &Path) -> Result<String> {
    git_output(
        root,
        &[
            "init".to_owned(),
            "--quiet".to_owned(),
            "--template=".to_owned(),
        ],
    )?;
    git_output(
        root,
        &["add".to_owned(), "--".to_owned(), "standards".to_owned()],
    )?;
    git_output(
        root,
        &[
            "-c".to_owned(),
            "user.name=Standards Fixture".to_owned(),
            "-c".to_owned(),
            "user.email=fixture@example.invalid".to_owned(),
            "-c".to_owned(),
            "core.hooksPath=/dev/null".to_owned(),
            "-c".to_owned(),
            "commit.gpgsign=false".to_owned(),
            "commit".to_owned(),
            "--quiet".to_owned(),
            "-m".to_owned(),
            "Synthetic source bundle".to_owned(),
        ],
    )?;
    let value = git_output(root, &["rev-parse".to_owned(), "HEAD".to_owned()])?;
    String::from_utf8(value)
        .map(|value| value.trim().to_owned())
        .map_err(|error| error.to_string())
}

#[test]
fn sync_is_pinned_repeatable_and_conflicts_do_not_partially_copy() -> TestResult {
    let source = Fixture::new()?;
    let target = Fixture::new()?;
    copy_canonical_bundle(&source.0)?;
    let commit = commit_bundle(&source.0)?;
    fs::write(target.0.join("unrelated.txt"), b"owned by another task\r\n")?;
    let mut args = Cli {
        source_root: source.0.clone(),
        target_root: target.0.clone(),
        repository: "AI-Ascension/.github".to_owned(),
        profile_id: "org-governance".to_owned(),
        owner: "ORG".to_owned(),
        source_commit: commit,
        ..Cli::default()
    };
    sync_bundle(&args)?;
    validate_root(&target.0, Some(FIXTURE_AS_OF))?;
    let profile_path = target.0.join("standards-profile.toml");
    let original_profile = fs::read(&profile_path)?;
    let mut edited_profile = original_profile.clone();
    edited_profile.extend_from_slice(b"\n# Unreviewed configuration edit\n");
    fs::write(&profile_path, edited_profile)?;
    assert!(validate_root(&target.0, Some(FIXTURE_AS_OF)).is_err());
    fs::write(&profile_path, original_profile)?;
    let lock = fs::read(target.0.join("standards.lock.json"))?;
    let metadata = fs::metadata(target.0.join("standards.lock.json"))?.modified()?;
    sync_bundle(&args)?;
    assert_eq!(fs::read(target.0.join("standards.lock.json"))?, lock);
    assert_eq!(
        fs::metadata(target.0.join("standards.lock.json"))?.modified()?,
        metadata
    );
    assert_eq!(
        fs::read(target.0.join("unrelated.txt"))?,
        b"owned by another task\r\n"
    );

    let conflicted = Fixture::new()?;
    fs::write(
        conflicted.0.join("standards-profile.toml"),
        b"existing profile",
    )?;
    args.target_root = conflicted.0.clone();
    assert!(sync_bundle(&args).is_err());
    assert!(!conflicted.0.join("standards").exists());
    assert_eq!(
        fs::read(conflicted.0.join("standards-profile.toml"))?,
        b"existing profile"
    );

    args.target_root = target.0.clone();
    let mut altered = fs::read(source.0.join("standards/BASELINE.md"))?;
    altered.extend_from_slice(b"\nUncommitted mutation\n");
    fs::write(source.0.join("standards/BASELINE.md"), altered)?;
    assert!(sync_bundle(&args).is_err());
    assert_eq!(fs::read(target.0.join("standards.lock.json"))?, lock);
    Ok(())
}

#[test]
fn digest_and_physical_inventory_changes_are_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    fs::create_dir(fixture.0.join("standards"))?;
    fs::write(fixture.0.join("standards/bytes.txt"), b"frozen\r\n")?;
    let profile = canonical_profile()?;
    let mut lock: LockFile =
        parse_json(&canonical_root().join("standards/conformance/valid-lock.json"))?;
    lock.files = vec![LockEntry {
        path: "standards/bytes.txt".to_owned(),
        sha256: sha256_hex(b"frozen\r\n"),
    }];
    let mut record = Vec::new();
    append_bundle_record(&mut record, "standards/bytes.txt", b"frozen\r\n");
    lock.source.bundle_digest = format!("sha256:{}", sha256_hex(&record));
    validate_lock_bytes(&fixture.0, &lock)?;
    fs::write(fixture.0.join("standards/bytes.txt"), b"frozen\n")?;
    assert!(validate_lock_bytes(&fixture.0, &lock).is_err());
    fs::write(fixture.0.join("standards/bytes.txt"), b"frozen\r\n")?;
    fs::create_dir(fixture.0.join("standards/target"))?;
    fs::write(
        fixture.0.join("standards/target/hidden.txt"),
        b"not compiler output",
    )?;
    assert!(validate_lock_bytes(&fixture.0, &lock).is_err());
    lock.files[0].path = "standards/../outside".to_owned();
    assert!(validate_lock_shape(&lock, &profile).is_err());
    Ok(())
}

#[test]
fn every_adopting_repository_has_a_valid_generated_profile() -> TestResult {
    let catalog: RepositoryMap = parse_yaml(&canonical_root().join("standards/repositories.yaml"))?;
    let mut checked = 0;
    for entry in catalog.repositories {
        if entry.adoption == "excluded" {
            continue;
        }
        let profile = generated_profile(
            &entry.profile_id,
            &entry.repository,
            &entry.owner,
            &"1".repeat(40),
            &format!("sha256:{}", "2".repeat(64)),
        )?;
        validate_profile(&profile)?;
        validate_required_checks(&profile)?;
        checked += 1;
    }
    assert_eq!(checked, 12);
    Ok(())
}

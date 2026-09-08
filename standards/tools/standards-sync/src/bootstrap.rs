//! Documentation/configuration checks for the two actual bootstrap repositories.
//! These checks do not activate product workspaces or evaluate client settings.
use super::*;
use pulldown_cmark::{Event, Parser, Tag};

pub(super) fn check(root: &Path) -> Result<()> {
    validate_root(root, None)?;
    let profile: Profile = parse_toml(&root.join("standards-profile.toml"))?;
    check_repository(root, &profile.repository)
}

fn expected_inputs(repository: &str) -> Result<&'static [&'static str]> {
    match repository {
        "AI-Ascension/ascension-watchdog" => Ok(&[
            "AGENTS.md",
            "README.md",
            "docs/architecture.md",
            "prompts/IMPLEMENTATION.md",
            "workspace-manifest.json",
            "docs/orchestration/task-dag.json",
        ]),
        "AI-Ascension/ascension-map-visualizer" => Ok(&[
            "AGENTS.md",
            ".codex/config.toml",
            "prompts/ASCENSION_MAP_VISUALIZER_ORCHESTRATION_PROMPT.md",
        ]),
        _ => Err(
            "bootstrap check is only applicable to the two reviewed planning repositories"
                .to_owned(),
        ),
    }
}

fn check_repository(root: &Path, repository: &str) -> Result<()> {
    let root = root.canonicalize().map_err(|error| error.to_string())?;
    for input in expected_inputs(repository)? {
        require_regular_file(&root.join(input))?;
    }
    let inventory = git_output(
        &root,
        &[
            "ls-files".to_owned(),
            "-z".to_owned(),
            "--cached".to_owned(),
            "--others".to_owned(),
        ],
    )?;
    let inventory = String::from_utf8(inventory).map_err(|_| "non-UTF-8 source path")?;
    let mut counts = [0usize; 4];
    let mut links = 0usize;
    for relative in inventory.split('\0').filter(|value| !value.is_empty()) {
        if relative.starts_with("standards/")
            || matches!(relative, "standards-profile.toml" | "standards.lock.json")
        {
            continue;
        }
        if !valid_relative_path(relative) {
            return Err("ambiguous bootstrap source path".to_owned());
        }
        let filename = Path::new(relative)
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if ["cargo.toml", "package.json", "composer.json"].contains(&filename.as_str()) {
            return Err(format!(
                "product manifest {relative} requires an owner-reviewed active profile"
            ));
        }
        let extension = Path::new(relative)
            .extension()
            .and_then(|value| value.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if !["md", "txt", "json", "toml", "yaml", "yml"].contains(&extension.as_str()) {
            if ["license", ".gitignore", ".editorconfig"].contains(&filename.as_str()) {
                admitted_file(&root, relative)?;
                continue;
            }
            return Err(format!(
                "unexpected bootstrap file {relative}; update the planning profile through owner review"
            ));
        }
        let path = admitted_file(&root, relative)?;
        let source = read_text(&path)?;
        match extension.as_str() {
            "md" | "txt" => {
                if source.trim().is_empty() {
                    return Err(format!("empty documentation input {relative}"));
                }
                links += check_links(&root, &path, &source)?;
                counts[0] += 1;
            }
            "json" => {
                let _: Value = serde_json::from_str(&source)
                    .map_err(|_| format!("invalid JSON source {relative}"))?;
                counts[1] += 1;
            }
            "toml" => {
                let _: toml::Value = toml::from_str(&source)
                    .map_err(|_| format!("invalid TOML source {relative}"))?;
                counts[2] += 1;
            }
            "yaml" | "yml" => {
                let _: serde_yaml::Value = serde_yaml::from_str(&source)
                    .map_err(|_| format!("invalid YAML source {relative}"))?;
                counts[3] += 1;
            }
            _ => {}
        }
    }
    if counts[0] == 0 || counts[1] + counts[2] + counts[3] == 0 {
        return Err("bootstrap source inventory is empty or incomplete".to_owned());
    }
    println!(
        "bootstrap sources: {} Markdown, {} JSON, {} TOML, {} YAML, {links} local file links checked; product/runtime and client option support unverified",
        counts[0], counts[1], counts[2], counts[3]
    );
    Ok(())
}

fn admitted_file(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut path = root.to_path_buf();
    for component in relative.split('/') {
        path.push(component);
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("symlinked bootstrap source or link".to_owned());
        }
    }
    require_regular_file(&path)?;
    Ok(path)
}

fn check_links(root: &Path, document: &Path, source: &str) -> Result<usize> {
    let mut count = 0;
    for event in Parser::new(source) {
        let destination = match event {
            Event::Start(Tag::Link { dest_url, .. } | Tag::Image { dest_url, .. }) => dest_url,
            _ => continue,
        };
        if destination.starts_with("https://")
            || destination.starts_with("http://")
            || destination.starts_with("mailto:")
            || destination.starts_with("//")
        {
            continue;
        }
        let file = destination.split(['#', '?']).next().unwrap_or("");
        if file.is_empty() {
            continue;
        }
        if file.contains(':') || file.contains('\\') || file.contains('%') {
            return Err(
                "ambiguous local Markdown link; use an explicit repository-relative file path"
                    .to_owned(),
            );
        }
        let base = document.parent().ok_or("document has no parent")?;
        let path = if let Some(relative) = file.strip_prefix('/') {
            root.join(relative)
        } else {
            base.join(file)
        };
        let resolved = path
            .canonicalize()
            .map_err(|_| format!("missing local Markdown link in {}", document.display()))?;
        let relative = resolved
            .strip_prefix(root)
            .map_err(|_| "Markdown link escapes repository")?;
        // Check the original lexical chain as well: canonicalization alone would
        // conceal a symlink that points to another file inside this repository.
        let lexical = path
            .strip_prefix(root)
            .map_err(|_| "Markdown link escapes repository")?;
        let mut cursor = root.to_path_buf();
        for component in lexical.components() {
            match component {
                std::path::Component::Normal(value) => cursor.push(value),
                std::path::Component::CurDir => continue,
                std::path::Component::ParentDir if cursor != root => {
                    cursor.pop();
                    continue;
                }
                _ => return Err("Markdown link escapes repository".to_owned()),
            }
            if fs::symlink_metadata(&cursor)
                .map_err(|error| error.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err("symlinked local Markdown link".to_owned());
            }
        }
        if !relative.as_os_str().is_empty() && !resolved.is_file() && !resolved.is_dir() {
            return Err("local Markdown target is not a source file or directory".to_owned());
        }
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn markdown_checks_links_but_does_not_execute_code_examples() -> TestResult {
        let fixture = super::super::conformance_tests::Fixture::new()?;
        fs::write(fixture.0.join("README.md"), "Fixture")?;
        let document = fixture.0.join("AGENTS.md");
        assert_eq!(
            check_links(
                &fixture.0,
                &document,
                "[valid](README.md)\n```\n[example](missing)\n```\n[external](https://example.invalid)"
            )?,
            1
        );
        assert!(check_links(&fixture.0, &document, "[missing](missing.md)").is_err());
        assert!(check_links(&fixture.0, &document, "[escape](../outside.md)").is_err());
        Ok(())
    }

    #[test]
    fn configuration_and_missing_or_new_product_inputs_fail() -> TestResult {
        let fixture = super::super::conformance_tests::Fixture::new()?;
        git_output(
            &fixture.0,
            &[
                "init".to_owned(),
                "--quiet".to_owned(),
                "--template=".to_owned(),
            ],
        )?;
        let repository = "AI-Ascension/ascension-map-visualizer";
        for file in expected_inputs(repository)? {
            let destination = prepare_managed_path(&fixture.0, file)?;
            fs::write(
                destination,
                if file.ends_with("toml") {
                    "[agents]\n"
                } else {
                    "Fixture documentation\n"
                },
            )?;
        }
        check_repository(&fixture.0, repository)?;
        fs::write(fixture.0.join(".codex/config.toml"), "[broken")?;
        assert!(check_repository(&fixture.0, repository).is_err());
        fs::write(fixture.0.join(".codex/config.toml"), "[agents]\n")?;
        fs::write(fixture.0.join("Cargo.toml"), "[package]\n")?;
        assert!(check_repository(&fixture.0, repository).is_err());
        fs::remove_file(fixture.0.join("Cargo.toml"))?;
        for relative in [
            "sub/Cargo.toml",
            "sub/package.json",
            "sub/composer.json",
            "tool.py",
            "tool.RS",
            "ignored/tool.rs",
            "config.yml",
        ] {
            let path = prepare_managed_path(&fixture.0, relative)?;
            fs::write(fixture.0.join(".gitignore"), "ignored/\n")?;
            fs::write(
                &path,
                if relative == "config.yml" {
                    "broken: ["
                } else {
                    "{}"
                },
            )?;
            assert!(
                check_repository(&fixture.0, repository).is_err(),
                "accepted {relative}"
            );
            fs::remove_file(path)?;
        }
        check_repository(&fixture.0, repository)?;
        fs::remove_file(fixture.0.join("AGENTS.md"))?;
        assert!(check_repository(&fixture.0, repository).is_err());
        Ok(())
    }
}

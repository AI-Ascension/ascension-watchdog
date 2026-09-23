//! Reviewed check plans for each adopting repository.

use super::managed::managed_profile_plan;
use super::{
    ProfilePlan, artifact_check, check, git_diff_check, rust_fast, rust_required, standards_check,
};
use crate::Result;

pub(crate) fn profile_plan(profile_id: &str, repository: &str) -> Result<ProfilePlan> {
    let plan = match (profile_id, repository) {
        ("org-governance", "AI-Ascension/.github") => ProfilePlan {
            scopes: vec!["markdown", "yaml", "json", "rust"],
            fast: vec![git_diff_check(), standards_check()],
            required: vec![
                check(
                    "standards-fmt",
                    "cargo +1.97.1 fmt --manifest-path standards/tools/standards-sync/Cargo.toml --check",
                    ".",
                ),
                check(
                    "standards-unit-tests",
                    "cargo +1.97.1 test --locked --manifest-path standards/tools/standards-sync/Cargo.toml",
                    ".",
                ),
                check(
                    "standards-clippy",
                    "cargo +1.97.1 clippy --locked --manifest-path standards/tools/standards-sync/Cargo.toml --all-targets -- -D warnings",
                    ".",
                ),
                check(
                    "standards-conformance",
                    "cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- fixture-check --root standards/conformance",
                    ".",
                ),
            ],
            extended: vec![check(
                "link-check",
                "bash tests/link-check-template.sh",
                ".",
            )],
        },
        ("rust-pure", "AI-Ascension/sts2-game-core") => ProfilePlan {
            scopes: vec!["rust"],
            fast: rust_fast(false),
            required: rust_required(),
            extended: Vec::new(),
        },
        ("rust-pure", "AI-Ascension/sts2-protocol") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-runtime-v3", "artifacts/runtime-v3-gameplay"),
                artifact_check("artifact-coop", "artifacts/coop-synchronization-v1"),
                artifact_check("artifact-poc-v1", "artifacts/poc-v1"),
                artifact_check("artifact-runtime-v1", "artifacts/runtime-v1"),
                artifact_check("artifact-runtime-v2", "artifacts/runtime-v2"),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(true),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-service", "AI-Ascension/sts2-gateway") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                artifact_check(
                    "artifact-runtime-v3",
                    "protocol-artifact/runtime-v3-gameplay",
                ),
                artifact_check("artifact-coop", "protocol-artifact/coop-synchronization-v1"),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(false),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-service", "AI-Ascension/sts2-mcp-server") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                artifact_check(
                    "artifact-runtime-v3",
                    "protocol-artifact/runtime-v3-gameplay",
                ),
                check(
                    "mcp-artifact-test",
                    "cargo test --locked --package sts2-mcp-server --test artifact",
                    ".",
                ),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(true),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-service", "AI-Ascension/sts2-harness") => {
            let mut required = rust_required();
            required.extend([
                artifact_check("artifact-poc-v1", "protocol-artifact/poc-v1"),
                artifact_check("artifact-runtime-v1", "protocol-artifact/runtime-v1"),
                artifact_check("artifact-runtime-v2", "protocol-artifact/runtime-v2"),
                check(
                    "patch-manifest",
                    "cargo test --package sts2-patch-diff --test patch_manifest --locked",
                    ".",
                ),
            ]);
            ProfilePlan {
                scopes: vec!["rust", "json", "contracts"],
                fast: rust_fast(false),
                required,
                extended: Vec::new(),
            }
        }
        ("rust-managed", "AI-Ascension/sts2-game-mod") => managed_profile_plan(),
        ("web-php", "AI-Ascension/aiascension.tech") => ProfilePlan {
            scopes: vec!["html", "css", "javascript", "php"],
            fast: vec![
                git_diff_check(),
                standards_check(),
                check("composer-validate", "composer validate --strict", "."),
                check("composer-lint", "composer run lint", "."),
                check("npm-format-check", "npm run format:check", "."),
                check("npm-lint", "npm run lint", "."),
                check("node-tests", "npm test", "."),
            ],
            required: vec![
                check("phpstan", "composer run analyse", "."),
                check("phpunit", "composer run test", "."),
                check("browser-check", "npm run test:browser", "."),
            ],
            extended: vec![check("composer-verify", "composer run verify", ".")],
        },
        ("web-static", "AI-Ascension/AI-Ascension.github.io") => ProfilePlan {
            scopes: vec!["html", "css", "javascript", "rust"],
            fast: vec![
                git_diff_check(),
                standards_check(),
                check("npm-format-check", "npm run format:check", "."),
                check("npm-lint", "npm run lint", "."),
                check("node-tests", "node --test tests/*.test.cjs", "."),
            ],
            required: vec![
                check("browser-check", "npm run test:browser", "."),
                check(
                    "pinned-gateway-recipe",
                    "node ../../scripts/check-recipe.mjs",
                    "recipes/gateway-lease-fence",
                ),
                check(
                    "pinned-mcp-recipe",
                    "node ../../scripts/check-recipe.mjs",
                    "recipes/mcp-seam",
                ),
            ],
            extended: Vec::new(),
        },
        ("operations", "AI-Ascension/ai-agent-observability") => ProfilePlan {
            scopes: vec!["shell", "yaml", "dockerfile", "systemd"],
            fast: vec![
                git_diff_check(),
                standards_check(),
                check("shell-syntax-init", "bash -n deploy/init.sh", "."),
                check(
                    "shell-syntax-key-bootstrap",
                    "bash -n deploy/laminar/bootstrap-project-key.sh",
                    ".",
                ),
                check(
                    "shellcheck",
                    "shellcheck --severity=warning deploy/init.sh deploy/laminar/bootstrap-project-key.sh tests/*.sh tests/fixtures/*",
                    ".",
                ),
            ],
            required: vec![
                check("bootstrap-tests", "bash tests/bootstrap.sh", "."),
                check(
                    "validation-regressions",
                    "bash tests/validation-regressions.sh",
                    ".",
                ),
                check(
                    "compose-policy-regressions",
                    "bash tests/compose-policy-regressions.sh",
                    ".",
                ),
                check(
                    "compose-source-regressions",
                    "bash tests/compose-source-regressions.sh",
                    ".",
                ),
                check(
                    "compose-invariants",
                    "bash tests/compose-invariants.sh",
                    ".",
                ),
                check(
                    "compose-config",
                    "docker compose --env-file deploy/.env.example -f deploy/compose.yaml config --quiet",
                    ".",
                ),
                check(
                    "compose-required-settings",
                    "bash tests/compose-required-settings.sh",
                    ".",
                ),
                check(
                    "compose-structured",
                    "bash tests/compose-structured.sh",
                    ".",
                ),
                check(
                    "dockerfile-mlflow",
                    "docker buildx build --check --file deploy/Dockerfile.mlflow deploy",
                    ".",
                ),
                check(
                    "dockerfile-laminar",
                    "docker buildx build --check --file deploy/Dockerfile.laminar deploy",
                    ".",
                ),
            ],
            extended: Vec::new(),
        },
        ("planning-bootstrap", "AI-Ascension/ascension-watchdog")
        | ("planning-bootstrap", "AI-Ascension/ascension-map-visualizer") => ProfilePlan {
            scopes: vec!["markdown", "configuration", "rust-tooling"],
            fast: vec![git_diff_check(), standards_check()],
            required: vec![check(
                "bootstrap-sources",
                "cargo +1.97.1 run --locked --manifest-path standards/tools/standards-sync/Cargo.toml -- check-bootstrap --root .",
                ".",
            )],
            extended: Vec::new(),
        },
        ("brand-package", "AI-Ascension/ascension-brand-overhaul") => {
            return Err(
                "brand package is explicitly excluded until its source-aware checksum review is complete"
                    .to_owned(),
            );
        }
        _ => {
            return Err(format!(
                "no verified profile command plan for {profile_id} at {repository}"
            ));
        }
    };
    Ok(plan)
}

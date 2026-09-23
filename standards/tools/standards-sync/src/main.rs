mod bootstrap;
mod bundle;
mod cli;
mod dates;
mod digest;
mod fixture;
mod identifiers;
mod model;
mod parsing;
mod paths;
mod planning;
mod validate;

use crate::bundle::sync_bundle;
use crate::cli::{fail, parse_cli, print_help};
use crate::validate::{fixture_check, validate_root};

type Result<T> = std::result::Result<T, String>;

fn main() {
    let args = match parse_cli() {
        Ok(value) => value,
        Err(error) => fail(&error),
    };

    let result = match args.command.as_str() {
        "validate" => validate_root(&args.root, args.as_of.as_deref()),
        "fixture-check" => fixture_check(&args.root),
        "check-bootstrap" => bootstrap::check(&args.root),
        "sync" => sync_bundle(&args),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        command => Err(format!("unknown command '{command}'; use 'help'")),
    };

    if let Err(error) = result {
        fail(&error);
    }
}

#[cfg(test)]
mod conformance_tests;

#[cfg(test)]
mod tests {
    use crate::dates::date_days;
    use crate::digest::sha256_hex;
    use crate::identifiers::{valid_commit, valid_relative_path, valid_target};
    use crate::validate::validate_schemas;

    #[test]
    fn sha256_matches_published_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn path_and_commit_guards_reject_ambiguous_inputs() {
        assert!(valid_commit("0123456789abcdef0123456789abcdef01234567"));
        assert!(!valid_commit("main"));
        assert!(valid_relative_path("standards/schemas/profile.schema.json"));
        assert!(!valid_relative_path("standards/../secret"));
        assert!(!valid_relative_path("/absolute"));
        assert!(valid_target("."));
        assert!(!valid_target("a/../secret"));
    }

    #[test]
    fn date_order_uses_calendar_days() {
        assert!(
            date_days("2026-02-28")
                .ok()
                .zip(date_days("2026-03-01").ok())
                .is_some_and(|(start, end)| start < end)
        );
        assert!(
            date_days("2024-02-29")
                .ok()
                .zip(date_days("2024-03-01").ok())
                .is_some_and(|(start, end)| start < end)
        );
    }

    #[test]
    fn canonical_schema_documents_have_semantic_metadata() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join("standards/schemas");
        assert!(validate_schemas(&root).is_ok());
    }
}

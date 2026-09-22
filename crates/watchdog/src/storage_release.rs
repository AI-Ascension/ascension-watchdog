//! Durable release-selection state owned by the watchdog store.
//!
//! Release bytes are validated by the protected catalog before these methods
//! are called.  This module owns only the small, transactional selector and
//! its recovery marker; it never opens an executable or changes authority
//! generations.  A `prepared` marker is intentionally retained across a
//! crash so the exact idempotency key can retry the final verification and
//! commit without allowing another release to leapfrog it.
//!
//! The implementation is split into cohesive child modules; this file stays
//! the `storage_release` coordinator so every existing path into the module
//! keeps working:
//!
//! - `identity` owns the selector metadata key namespace, the selector value
//!   types and the strict parse and validation of release identities.
//! - `transactions` owns activation and rollback preparation and completion,
//!   including the retained `prepared` recovery marker, the receipt contract
//!   and the restore/rekey clearing transaction.
//! - `queries` owns the read-only selector projection used by status,
//!   recovery and owner opens.
//!
//! Every resulting module is below the 1,000-line target, so no exception has
//! to be documented.  The functional acceptance tests stay in this file and
//! still exercise the child modules together.

// `storage` is itself declared with `#[path]`, so this coordinator must name
// the child files explicitly instead of relying on directory derivation.
#[path = "storage_release/identity.rs"]
mod identity;
#[path = "storage_release/queries.rs"]
mod queries;
#[path = "storage_release/transactions.rs"]
mod transactions;

pub use identity::{
    PendingReleaseActivation, ReleaseIdentity, ReleaseSelection, ReleaseSelectionState,
};
pub(crate) use transactions::clear_release_selection_tx;

#[cfg(test)]
mod tests {
    use super::ReleaseSelectionState;
    use super::identity::ACTIVE_DIGEST_KEY;
    use crate::config::WatchdogConfig;
    use crate::error::Result;
    use crate::storage::{
        OperatorCapability, OperatorCommand, OperatorCommandContext, OperatorCommandOutcome,
        SingletonLock, Store,
    };
    use serde_json::{Value, json};
    use tempfile::TempDir;
    use uuid::Uuid;

    fn context(key: &str, request_id: &str) -> OperatorCommandContext {
        OperatorCommandContext::new(
            request_id,
            key,
            "AdminToken",
            OperatorCapability::Admin,
            "a".repeat(64),
        )
        .expect("valid operator context")
    }

    fn response(id: &str, digest: &str, rollback: bool) -> Value {
        response_with_previous(id, digest, rollback, None)
    }

    fn response_with_previous(
        id: &str,
        digest: &str,
        rollback: bool,
        previous: Option<(&str, &str)>,
    ) -> Value {
        json!({
            "kind": "ReleaseActivation",
            "value": {
                "release_id": id,
                "release_digest": digest,
                "previous_release_id": previous.map(|value| value.0),
                "previous_release_digest": previous.map(|value| value.1),
                "rollback": rollback,
            }
        })
    }

    fn fixture() -> (TempDir, WatchdogConfig, Store, SingletonLock) {
        let temp = tempfile::tempdir().expect("temporary release selector store");
        let config = WatchdogConfig {
            database: temp.path().join("watchdog.sqlite3"),
            ..WatchdogConfig::default()
        };
        let store = Store::initialize(&config.database, &config).expect("initialize store");
        let owner = SingletonLock::acquire(&config.database).expect("owner lock");
        (temp, config, store, owner)
    }

    #[test]
    fn prepared_activation_survives_reopen_and_exact_retry_commits_once() -> Result<()> {
        let (_temp, config, mut store, owner) = fixture();
        let first = context("activate-one", &Uuid::new_v4().to_string());
        let digest = "b".repeat(64);
        let prepared = store.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &digest,
            false,
            10,
        )?;
        assert_eq!(prepared.state, ReleaseSelectionState::Prepared);
        drop(store);
        drop(owner);

        let mut reopened = Store::open(&config.database, &config)?;
        let pending = reopened.release_selection()?;
        assert_eq!(pending.state, ReleaseSelectionState::Prepared);
        assert_eq!(
            pending
                .pending
                .as_ref()
                .map(|value| value.release.release_id.as_str()),
            Some("release-one")
        );
        let owner = SingletonLock::acquire(&config.database)?;
        let replay_prepare = reopened.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &digest,
            false,
            11,
        )?;
        assert_eq!(replay_prepare.state, ReleaseSelectionState::Prepared);
        let response = response("release-one", &digest, false);
        let committed = reopened.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &digest,
            false,
            &response,
            12,
        )?;
        assert!(matches!(committed, OperatorCommandOutcome::Accepted(_)));
        let active = reopened.release_selection()?;
        assert_eq!(active.state, ReleaseSelectionState::Active);
        assert_eq!(
            active
                .active
                .as_ref()
                .map(|value| value.release_id.as_str()),
            Some("release-one")
        );
        assert!(active.pending.is_none());

        let replay = reopened.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &digest,
            false,
            &response,
            13,
        )?;
        assert!(matches!(replay, OperatorCommandOutcome::Replayed(_)));
        assert_eq!(reopened.operator_command_count()?, 1);
        Ok(())
    }

    #[test]
    fn rollback_is_bound_to_previous_release_and_cannot_toggle_arbitrary_catalog_entries()
    -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let first = context("activate-one", &Uuid::new_v4().to_string());
        let first_digest = "b".repeat(64);
        store.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &first_digest,
            false,
            10,
        )?;
        let first_response = response("release-one", &first_digest, false);
        store.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &first_digest,
            false,
            &first_response,
            11,
        )?;

        let second = context("activate-two", &Uuid::new_v4().to_string());
        let second_digest = "c".repeat(64);
        store.prepare_release_activation(
            &owner,
            &second.request_id,
            &second.idempotency_key,
            "release-two",
            &second_digest,
            false,
            12,
        )?;
        let second_response = response_with_previous(
            "release-two",
            &second_digest,
            false,
            Some(("release-one", first_digest.as_str())),
        );
        store.complete_release_activation(
            &owner,
            &second,
            "release-two",
            &second_digest,
            false,
            &second_response,
            13,
        )?;

        let rollback = context("rollback-two", &Uuid::new_v4().to_string());
        assert!(
            store
                .prepare_release_activation(
                    &owner,
                    &rollback.request_id,
                    &rollback.idempotency_key,
                    "not-the-previous-release",
                    &first_digest,
                    true,
                    14,
                )
                .is_err()
        );
        store.prepare_release_activation(
            &owner,
            &rollback.request_id,
            &rollback.idempotency_key,
            "release-one",
            &first_digest,
            true,
            15,
        )?;
        let rollback_response = response_with_previous(
            "release-one",
            &first_digest,
            true,
            Some(("release-two", second_digest.as_str())),
        );
        store.complete_release_activation(
            &owner,
            &rollback,
            "release-one",
            &first_digest,
            true,
            &rollback_response,
            16,
        )?;
        let selection = store.release_selection()?;
        assert_eq!(
            selection
                .active
                .as_ref()
                .map(|value| value.release_id.as_str()),
            Some("release-one")
        );
        assert_eq!(
            selection
                .previous
                .as_ref()
                .map(|value| value.release_id.as_str()),
            Some("release-two")
        );
        Ok(())
    }

    #[test]
    fn activation_receipt_must_describe_the_prepared_selector() -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let activation = context("activate-one", &Uuid::new_v4().to_string());
        let digest = "b".repeat(64);
        store.prepare_release_activation(
            &owner,
            &activation.request_id,
            &activation.idempotency_key,
            "release-one",
            &digest,
            false,
            10,
        )?;
        let error = store
            .complete_release_activation(
                &owner,
                &activation,
                "release-one",
                &digest,
                false,
                &response("different-release", &digest, false),
                11,
            )
            .expect_err("a mismatched receipt cannot publish the selector");
        assert!(error.to_string().contains("response does not match"));
        assert_eq!(
            store.release_selection()?.state,
            ReleaseSelectionState::Prepared
        );
        assert_eq!(store.operator_command_count()?, 0);
        Ok(())
    }

    #[test]
    fn prepared_activation_rejects_a_request_id_already_in_the_operator_ledger() -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let existing = context("existing-command", &Uuid::new_v4().to_string());
        store.admit_operator_command(
            &owner,
            &existing,
            OperatorCommand::JobSubmit,
            &json!({"kind": "accepted", "value": {"queued": true}}),
            10,
        )?;
        let collision = context("new-activation", &existing.request_id);
        let error = store
            .prepare_release_activation(
                &owner,
                &collision.request_id,
                &collision.idempotency_key,
                "release-one",
                &"b".repeat(64),
                false,
                11,
            )
            .expect_err("a reused request UUID must not strand a prepared marker");
        assert!(error.to_string().contains("request id already belongs"));
        assert_eq!(
            store.release_selection()?.state,
            ReleaseSelectionState::None
        );
        Ok(())
    }

    #[test]
    fn prepared_activation_rejects_a_changed_active_identity() -> Result<()> {
        let (_temp, _config, mut store, owner) = fixture();
        let first = context("activate-one", &Uuid::new_v4().to_string());
        let first_digest = "b".repeat(64);
        store.prepare_release_activation(
            &owner,
            &first.request_id,
            &first.idempotency_key,
            "release-one",
            &first_digest,
            false,
            10,
        )?;
        store.complete_release_activation(
            &owner,
            &first,
            "release-one",
            &first_digest,
            false,
            &response("release-one", &first_digest, false),
            11,
        )?;

        let second = context("activate-two", &Uuid::new_v4().to_string());
        let second_digest = "c".repeat(64);
        store.prepare_release_activation(
            &owner,
            &second.request_id,
            &second.idempotency_key,
            "release-two",
            &second_digest,
            false,
            12,
        )?;
        store.conn.execute(
            "UPDATE metadata SET value=? WHERE key=?",
            rusqlite::params!["d".repeat(64), ACTIVE_DIGEST_KEY],
        )?;
        let error = store
            .complete_release_activation(
                &owner,
                &second,
                "release-two",
                &second_digest,
                false,
                &response_with_previous(
                    "release-two",
                    &second_digest,
                    false,
                    Some(("release-one", first_digest.as_str())),
                ),
                13,
            )
            .expect_err("changed active identity must block completion");
        assert!(error.to_string().contains("active release changed"));
        assert_eq!(
            store.release_selection()?.state,
            ReleaseSelectionState::Prepared
        );
        Ok(())
    }
}

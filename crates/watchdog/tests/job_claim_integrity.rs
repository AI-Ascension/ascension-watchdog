use ascension_watchdog::{DesiredMode, Store, WatchdogConfig};
use serde_json::json;

#[test]
fn malformed_or_changed_payload_cannot_commit_a_claim() {
    for (replacement, matching_digest) in [
        ("{invalid", false),
        ("{\"approved\":false}", false),
        ("{invalid", true),
        ("{\"oversized\":\"abcdefghijklmnopqrstuvwxyz\"}", true),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let config = WatchdogConfig {
            database: directory.path().join("state.sqlite"),
            desired_mode: DesiredMode::Running,
            max_payload_bytes: 32,
            ..WatchdogConfig::default()
        };
        let mut store = Store::initialize(&config.database, &config).unwrap();
        let job = store
            .submit_job_at("episode", &json!({"approved":true}), 1)
            .unwrap();
        let raw = rusqlite::Connection::open(&config.database).unwrap();
        raw.execute(
            "UPDATE jobs SET payload=? WHERE id=?",
            rusqlite::params![replacement, job.id],
        )
        .unwrap();
        if matching_digest {
            raw.execute(
                "UPDATE jobs SET payload_digest=? WHERE id=?",
                rusqlite::params![
                    ascension_watchdog::config::hex_digest(replacement.as_bytes()),
                    job.id
                ],
            )
            .unwrap();
        }
        let audit_before: i64 = raw
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            .unwrap();
        assert!(store.claim_next_job("worker", 2).is_err());
        let state: (String, i64) = raw
            .query_row(
                "SELECT status, attempt_count FROM jobs WHERE id=?",
                [&job.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(state, ("queued".to_owned(), 0));
        let attempts: i64 = raw
            .query_row("SELECT COUNT(*) FROM attempts", [], |row| row.get(0))
            .unwrap();
        let audit_after: i64 = raw
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(attempts, 0);
        assert_eq!(audit_before, audit_after);
    }
}

# `watchdog-admin-v1` schemas

`manifest.json` identifies the closed request and response schemas and the
implementation bounds. The Rust transport performs recursive duplicate-key
rejection before these schemas are applied; JSON Schema's
`additionalProperties: false` covers unknown fields but cannot by itself
express duplicate member rejection or the capability-to-command matrix.

The `token` member exists only in the authenticated request transport. It is
not copied to response types, status views, audits, fixtures, or release
manifests. Backup/restore and release commands carry logical approved IDs and
digests rather than arbitrary local paths. No schema variant represents a
gameplay mutation, game settlement, lease grant, host fence, or generic proxy.

The schema is a contract artifact, not evidence that a watchdog service,
database, host, or game is live. Native Unix transport and main-loop queue
tests are maintained separately under the Rust test suite.

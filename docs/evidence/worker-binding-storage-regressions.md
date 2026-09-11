# Worker binding and absent process identity regressions

Classification: confirmed local storage and synthetic-process evidence.

Native watchdog-to-harness composition exposed two store defects. A component
with SQL NULL process identity now decodes as `None`, just like an absent row;
malformed non-null identity JSON still fails. The storage regression checks
missing, NULL, reopen, and corrupted identity cases.

Reapplying an identical immutable worker binding is now a true no-op. It retains
the original timestamp and audit rows even if the supplied wall clock moves
backwards. The existing row decoder still validates stored timestamps before
equality is checked; changed bindings continue to reject, and first-insert
validation and auditing are unchanged. Three focused tests cover forward and
backward replay, reopen, immutable field conflicts, and corrupt stored time.

Root integrated both repairs and ran format, warnings-as-errors Clippy, and the
workspace/all-target/all-feature locked matrix successfully. The three
`worker_binding_clock` tests also passed independently in review. No migrations,
authority generations, control-mode ordering, or job-claim rules were changed.

The exploratory real harness smoke subsequently reached authenticated Running
control but did not prepare a job handoff within its observation deadline. That
composition remains failed evidence under separate diagnosis; these storage
tests do not imply a passing service, provider, or game-host campaign.

# A8 stale operation isolation review

Classification: source-derived concern, independent reproduction requested.
Candidate `46c82ef` remains unintegrated.

In the candidate's `v3_handle_value`, stale dispatch and stale wait/recovery
branches call `mark_runtime_operation_unknown(operation_id)` before comparing
the request's instance, lease ID and epoch to its retained session. The operation
lookup is keyed only by operation ID. The helper updates that operation's status
and removes its queue row without checking session or authority context.

This appears to allow a stale request naming another retained operation to
alter its execution state. V24 must reproduce or disprove the cross-session
case and verify that any eventual fix rejects unauthorized context before
mutating rows. Correctly preserving UNKNOWN on genuine expiry must not grant
stale clients authority over a different operation.

The newly persisted immutable ticket deadline and legacy queued-operation
transaction address the preceding review direction, but these source changes
and author test results do not yet establish complete fixture conformance.

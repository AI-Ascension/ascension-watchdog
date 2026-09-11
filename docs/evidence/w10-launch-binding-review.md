# W10 launch binding review

Classification: source-derived blockers in `62e1f27`; not integrated.

## Dynamic Windows session selector

`validate_persisted_launch_binding` maps `ActiveUser` to `None` and requires
the proof's `session_id` to equal that value. The Windows platform always
records `Some(resolved_session_id)` in its process proof. Consequently a valid
active-user launch is rejected. The selector must remain bound in the original
request digest, while the resolved session is checked according to platform
semantics. An explicit selector must still require its exact session.

Requested regression: valid Windows active-user proof, invalid/missing resolved
session, and mismatched explicit session.

## Implicit migration

The candidate's common existing-store opener migrates schema 1 on any writable
open, including the compatibility `Store::open` path. This changes the prior
explicit-migration contract and is not restricted to an owner-authorized
migration operation. Read-only and ordinary compatibility opens must not
silently upgrade state. Check ownership, deployment and configuration before
allowing migration, and prove rejection leaves version/columns unchanged.

Both defects were returned to W10. Historical launch-incarnation binding remains
required; these corrections must not replace it with current-generation checks
or infer legacy bindings from supplied proofs.

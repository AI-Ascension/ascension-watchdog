# Windows process integrity boundary

The Windows adapter receives an allowlisted executable path and a separate
approved SHA-256 digest for every role.  Before `CreateProcess` it opens the
canonical executable with write/delete sharing denied, records the kernel file
identity, hashes the bytes through that handle, and rejects a digest mismatch.
It repeats the path identity and byte barrier while the child is suspended,
then assigns the child to its named Job Object before resuming it.

The approved executable digest is a pre-execution admission check; it is not a
claim that a path remains a complete release identity after process creation.
The retained directory handle prevents the release directory object from being
removed or renamed while the owner lives, but it does not hash or pin the
contents of dependent DLLs.  Loader search policy and dependent-module
integrity remain a separate Windows validation requirement.

If `CreateProcess` succeeds but wrapping either returned native handle fails,
the launcher marks the failure as post-creation and runs the exact Job cleanup
path.  If cleanup cannot be proven, the caller receives cleanup uncertainty and
must retain the durable launch intent for reconciliation.

Native Windows execution remains unverified from this Linux worktree.  The
Windows synthetic suite is the required runtime evidence for the live Job
Object and launch boundary.

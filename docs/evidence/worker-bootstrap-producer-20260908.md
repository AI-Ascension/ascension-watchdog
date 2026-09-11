# Supervisor-owned Linux worker bootstrap integration

This change joins the previously published frame, launch-binding storage, and
Linux worker-pipe components. It does not establish an end-to-end deployed worker.

For a native configured worker, the supervisor captures its own held executable
and process birth identity, creates one immutable frame, persists the prepared
launch intent and frame binding, then passes that frame to the native launcher.
The helper's post-GO admission check requires the exact stored boot/frame binding
and current durable Running mode. Binding failure cleans the still-unspawned
intent; a cleanup failure retains quarantine.

A fresh child retains the frame binding in memory. Recovered configured workers
are cleanup authority only: they cannot inherit the new supervisor's worker
credential. The runtime retains and quarantines the exact recovered handle before
stopping it. Uncertain stop retains quarantine and prevents replacement.

## Native Linux image identity correction

The native launcher executes sealed memfd snapshots. `/proc/PID/exe` therefore
has a deleted memfd name and a different inode from the configured executable.
Canonicalizing that name incorrectly made native process observation fail. The
adapter now reads the procfs link, retaining its existing seal/digest checks.

Worker authentication has an internal owned-native constructor, selected only
after the runtime inspects its held native child. It verifies the current OS boot
and process start ticks against the adapter's `boot-id:start-ticks` token, hashes
the actual fully sealed process image under a deadline, and retains that image.
Socket authentication still requires exact PID, birth token, UID/GID, and held
image identity. Public file-backed construction cannot select sealed-image policy.
The durable ownership token is not rewritten or weakened.

## Evidence

On Linux, the focused library filter `sealed_` passed three tests with one ignored
fixture entry point. The parent test actually executes that entry point from a
sealed image and connects to its Unix socket. It verifies successful peer
authentication and rejection of wrong boot, birth ticks, inode, or missing private
sealed-image proof. Another real sealed `/bin/sleep` child verifies both native
process observation paths. This requires no service installation or cgroup change.

The debug fixture permits 90 seconds for hashing a symbol-heavy test image;
production native capture remains limited to five seconds. Debug success is not
evidence of that release-time budget. The optimized sealed-peer regression also
passed with its production five-second capture budget (whole test: 0.12 seconds).
Strict library/test Clippy passed. Existing producer unit tests separately
exercise current binding, exact helper metadata, failed binding cleanup, and
recovered-worker cleanup/uncertainty. Their owned-child fixtures do not prove
native cgroup reopening.

The final Linux library run passed 101 tests, with four explicitly ignored
entry points or privileged host tests (156.08 seconds). The two subprocess
fixture entry points are exercised by their parent tests; the delegated-cgroup
and installed-broker host tests remain unexecuted.

The workspace/all-target/all-feature serial suite subsequently passed. After
independent review, the focused sealed-peer tests were extended and passed
again (two tests, one parent-invoked fixture entry point ignored; 47.31 seconds).
They additionally reject unsealed and incompletely sealed images, actual digest
mismatch, initial peer-account mismatch, an actual same-PID exec into another
image, and the exited process. The public raw-token constructor is documented
and tested to reject native Linux ownership tokens; it cannot silently select
the private sealed-image policy.

## Remaining gates

Windows producer delivery is still explicitly unavailable in this change. Native
Windows pipe execution, a real delegated-cgroup controller-to-harness exchange,
service restart, cold boot, gameplay, provider behavior, release activation, and
soak are not established by these tests. Missing privileged host evidence must
remain separate from source/build and unprivileged process evidence.

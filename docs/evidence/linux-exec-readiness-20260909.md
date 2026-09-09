# Linux procfs exec-readiness regression

Hosted CI run `34296482615` at `a04c132` observed a newly spawned child still
reporting the parent test executable through `/proc/PID/exe`. Its intended
executable was `/usr/bin/dash`. The exact-process assertion failed closed;
broker peer-path and an unsealed-image fixture assertion also failed in that run.

The two sealed-image fixtures now wait under a five-second bound for procfs to
reference the exact device/inode of their held memfd before running observation
or missing-seal assertions. This is a test readiness witness, not a retry of a
worker command or an authentication relaxation. A different image cannot satisfy
the wait by matching a name, path prefix, or elapsed sleep.

Both focused tests and strict library/test Clippy passed after this change.
Production direct-child launch readiness and the broker fixture's equivalent
readiness are tracked separately; this document does not claim hosted CI is green.

# Windows terminal owner validation

Hosted run `34297678085` reached the native synthetic suite after the platform
library repair. Leader-exit/crash tests encountered unavailable image metadata
after termination, and prepared-Job cleanup observed a brief gap between empty
Job accounting and the exact leader handle becoming signaled.

The process owner now retains a private, non-serialized witness only after full
live PID, birth, immutable digest, image path, session, and Job membership checks.
Terminal image-metadata unavailability is accepted only for that already-witnessed
owner. A fresh reopened owner starts without the witness and must validate image
while live; persisted PID/birth fields cannot manufacture it. A fresh terminal
reopen, including exit during the final session/membership checks, is rejected
without a prior local witness. This intentionally favors closed admission over
adoption when terminal metadata cannot prove complete ownership. Initial unwitnessed image-query errors
still fail closed. Cleanup assertions wait on their exact retained handles within
the existing five-second test bound after Job termination.

Portable native fixtures explicitly select `CurrentService`, not literal service
session 0. They are synthetic process tests, not installed-service validation.
Cross-built tests locate their checked-in executable fixture beside the test image.

Root validation on Windows, using copied and hash-verified binaries in a fresh
owned temporary directory, `--test-threads=1 --nocapture`, and a 55-second outer
deadline:

- Initial repair: four passed, one failed on another immediate post-stop handle
  assertion. No success was claimed from that run.
- After bounded exact-handle waits: five passed, 6.24 seconds, exit 0.
- With the terminal forged-image reopen regression: six passed, 8.38 seconds,
  exit 0. This includes leader/descendant cleanup, prepared-Job recovery,
  crash/restart, immutable-image barriers, and rejection of an unwitnessed
  alternate image on terminal reopen.
- After additionally rejecting fresh terminal owners at both initial and final
  identity observations: six passed, 8.23 seconds, exit 0.

Final native test SHA-256:
`ce9fc9d660fff32b1c533e21b0f0216f7a8e8aa483dd243d0b079310c5f65ea7`.
Synthetic fixture SHA-256:
`90c2ceb5f5ca370106364131a0c6b407c43526f5ad1906c4c97fb11bbbd7c45b`.

Windows-target build, strict all-target Clippy, formatting, and diff checks passed.
Integrated/hosted CI must still validate the published candidate. No service,
account-security change, gameplay, reboot, release activation, or soak occurred.

## Initial witness before resumption

The integrated launcher now constructs and verifies the complete process owner
while its initial thread remains suspended, then runs durable admission and resumes
it. This prevents a legitimate immediate exit from racing the first live identity
check. A failed `ResumeThread` error is captured before dropping the caller's guard,
so guard cleanup cannot overwrite the native error code.

Native integrated checks passed: seven synthetic tests in 9.27 seconds and five
worker-pipe/guard tests in 2.67 seconds, both exit 0. The synthetic suite now includes
a zero-delay process exit and the forged terminal reopen regression. Exact hashes:

- Synthetic suite: `6767c9891ce61796a53d7e134b7c69d631431428b131ae9d8731eaf3c645a8ba`
- Worker suite: `f33b20c87843cfc7d23b0424abf05b579cdca1af6f9797bcc72b6fc2e7c04383`
- Synthetic fixture: `edb4d615091ac47bf8809703e155c07d2b7422595ea4d932a48c62f9dcef52fc`

## Verified-owner metadata teardown window

Hosted run `34310012164` at `6d862658a58e417237819e58a9b75fec98d238fe`
failed `native_leader_exit_still_forces_job_descendant_cleanup` with
`QueryFullProcessImageNameW` error 5. Source inspection identifies a remaining
race: image metadata may become unavailable during termination before the held
process handle reports signaled. The observed error is not treated as a generic
termination signal.

The private per-owner live witness now avoids subsequent image/session/Job
re-query after every held-handle PID, creation token, immutable digest and wait
status check. Its acquire/release semantics and initial full verification remain
unchanged. A fresh reopen has no witness and cannot inherit it from serialized
identity. No blanket access-denied fallback, PID-only authority, or containment
relaxation was introduced. Independent source review found no blocker.

Root rebuilt the integrated native synthetic target and copied it with its
checked-in fixture, verifying both SHA-256 values. All seven tests passed in
three consecutive native runs: 9.52, 9.14 and 9.15 seconds, each exit 0. This
includes leader/descendant cleanup and the unchanged rejection of a forged
terminal reopen without a local live witness.

- Test artifact: `3129def84f296d81ec2fddcc499d227f4a2721a7d005769a5fd9ecb0f47838e6`
- Synthetic fixture: `1964c7d896469b76614e0208044649abe6a881d2e550178c6eec18c6ddc7437f`

These are native subprocess results, not installed-service or reboot evidence.
The new exact-revision hosted run remains required.

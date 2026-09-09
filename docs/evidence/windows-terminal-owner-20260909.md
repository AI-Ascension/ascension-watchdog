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
adoption when terminal metadata cannot prove complete ownership. Live image-query errors
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

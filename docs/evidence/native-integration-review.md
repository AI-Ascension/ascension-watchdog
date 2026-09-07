# Native integration review

Root reviewed the complete changes in native runtime `1b7375f`, Linux boundary
`f5fc280`, and Windows boundary `085b40f`. This is an integration checkpoint,
not release approval. Linux was integrated as `13c0e71`; Windows and native
runtime remain pending repairs and independent review.

## Confirmed targeted Linux evidence

```sh
cargo test --locked -p ascension-watchdog --test linux_boundary
cargo test --locked -p ascension-watchdog --lib platform::linux_launcher::tests -- --test-threads=1
```

Both exited 0: three boundary tests and ten launcher tests passed. One gated
native boundary test was ignored. That ignored test currently only checks
adapter construction; even running it would not prove descendant containment.
Descriptor replacement coverage proves rename resistance, not immutable bytes
against in-place writes. No native service or game-host evidence is claimed.
Linux workspace/all-target/all-feature Clippy with locked dependencies and
warnings denied also exited 0 after integration.

## Open source-derived blockers

Returned to the respective authors for separate fixes and regressions:

- Linux descriptor-bound execution still permits in-place modification between
  hashing and execution. Opened-handle type checks, nonblocking special-file
  rejection, and cumulative hash bounds are also needed.
- Linux failed-child cleanup originally called blocking `wait()` after a
  possible kill failure. Follow-up `7bad5db`, integrated as `fb7c497`, replaces
  these waits with deadline-bound polling and retains uncertain containment.
  Nine focused Linux process tests passed (one native test ignored), including
  injected termination failure and unproven-reap regressions. Root also removed
  an introduced production `expect` from the cleanup error path. Full Linux
  warnings-denied Clippy and formatting checks passed after integration.
- Runtime launch-error handling clears its durable intent even if containment
  cleanup is uncertain. Prepared-intent recovery does not yet use exact planned
  containment cleanup; abort cleanup can discard retained child ownership.
- Linux helper authorization checks only the requested cgroup basename and
  copies the full caller-supplied path into its authorization. Bind that path
  to the approved delegated root.
- Native recovery proof incarnation is only checked for nonemptiness; bind it
  to admission context. Session zero and empty native output snapshots do not
  prove graphical-session handling or bounded output capture.
- Windows executable verification opens a second read handle while retaining
  a zero-share handle. This conflicts with documented sharing rules, including
  for opens by the same process. Use compatible read sharing while continuing
  to deny write/delete, and test actual suspended-child launch.
  [Microsoft file-sharing rules](https://learn.microsoft.com/en-us/windows/win32/fileio/creating-and-opening-files).
- Windows replay-policy configuration can reset sequence state after a
  disconnect without requiring a new epoch/nonce. Pipe deadlines also need
  enforcement on successful-progress iterations, not only empty-read retries.

The Windows administrative integration must select one pipe worker and supply
the expected server executable. The protected payload-reader follow-up
`4823bdb` overlaps Windows boundary files and must be reviewed and integrated
after their repaired version. No remote writes, service installation, reboot,
provider/game launch, or release activation occurred during this review.

## Integrated follow-up, 2026-09-07

Source revisions `604f954` and `23e34e4` wire the native runtime manager and
retain uncertain launch ownership. Root revision `4d738fa` restores binding
between the Linux helper's requested cgroup leaf and its durable planned
containment. The two runtime-manager unit tests and strict Linux workspace
Clippy passed. Full delegated-root binding and Windows prepared-intent recovery
remain under independent review. Native output capture is explicitly disabled;
this is an outstanding requirement, not a captured-empty-output result.

Windows boundary revisions `4bb18ac` and `b6ad17a`, followed by `f0eb0e5`, repair
read sharing, replay reset, absolute pipe deadlines, and the exclusive-worker
and expected-server-image caller settings. Eight portable tests and nine Unix
admin integration tests passed. Windows-native execution remains unverified.

The integrated workspace test run after `4d738fa` returned exit 101: the
synthetic descendant-cleanup regression failed, as did owner-local executable
and cleared-PID test assumptions. The latter tests were repaired without
weakening admission or cleanup requirements: use an owner-local test executable
and a separate test PID witness, while asserting active PID authority is cleared.
All five tests in those two suites then passed. Synthetic descendant cleanup
remains an open implementation defect assigned to P7. This is not a green
workspace result or native service evidence.

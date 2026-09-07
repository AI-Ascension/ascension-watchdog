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
- Linux failed-child cleanup calls blocking `wait()` after a possible kill
  failure, before starting the containment deadline.
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

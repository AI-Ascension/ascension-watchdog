# Native boundary integration checkpoint

Evidence classification: confirmed command outcomes and source-derived gaps.
This checkpoint is not implementation, deployment, or recovery acceptance.

## Integrated source

- Watchdog: `506b25742ef7c37158fb84fde00bf74ede46835f`.
  Root ran `cargo test --workspace --all-targets --all-features --locked --offline`
  on Linux with a distinct build directory, two build jobs, and incremental
  compilation disabled: exit 0. `cargo fmt --all --check`: exit 0.
  Windows-only test modules execute zero tests on Linux; this is not Windows
  service evidence. Strict integrated Clippy remains in progress.
- Harness: `8f6bf7d030556ed42c28a88eb11fe5d59864ca50` integrates bounded durable
  row materialization and canonical action-envelope validation. Independent
  exact-source review of `2dd708e72b65622c07d0df7f86467ed7f08ae32f` passed 21
  execution-store tests, five startup tests, and 81 runtime tests. Root combined
  workspace validation is in progress; these component results are not a
  combined release-set pass.

## Actual Windows evidence

Root cross-built and executed the named-pipe transport test binary on Windows.
Binary SHA-256:
`4dafae73dccfac1ad8a05f9ce86bd7b7b5b7716d9caa65ce5b507dd4e4f5371f`.
Command arguments: `--nocapture --test-threads=1`.
Result: exit 101, three passed and one failed.
`native_pipe_round_trip_checks_peer_sid_and_server_identity` failed because the
peer closed before frame completion. Bounded server-response draining is under
repair; cross-compilation alone had not exposed this defect.

Independent native temporary-file probes also confirmed that protected-storage
candidate `d81a63f15a27dd010dcaf0e0c3912437fcecf8e9` cannot create Windows files
with its current ANSI-marshaled security-descriptor call. Linux review confirmed
a FIFO open can block before type validation and exclusive file sharing was not
enforced. ACL, alternate-stream, handle-lifetime, and identity-resource defects
also require repairs. This candidate is not integrated or accepted.

Installer candidate `d96e92be870f887de994fae67d649c8c968128b6` is not accepted:
native PowerShell 5.1 lacks its absolute-path API; its file-information layout
reads file size as volume identity; its write-rights mask rejects ordinary read
grants; and its ACL walk omits the leaf file. Repair of the explicitly bounded
native pinning helper now has root approval and requires independent review.

## Remaining integration work

Gateway allocation producer `23aa476c3337875b879efa823eb023d18294c8f1` is under
independent review. It adds a versioned acquired-lease authority context and
current fence. The harness still needs to consume acquired authority and persist
each operation's original context instead of reconstructing it from environment
configuration. Worker handoff transport and both owner-local ledgers also remain
under implementation/review. None of these candidates proves end-to-end recovery.

No services were installed, games or providers launched, hosts rebooted, or
releases activated for this checkpoint. Native tests used bounded IPC or newly
created temporary file fixtures, not service-manager or gameplay operations.

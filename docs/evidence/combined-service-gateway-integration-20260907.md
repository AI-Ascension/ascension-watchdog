# Service and gateway local integration

Classification: confirmed source/build and synthetic-test evidence only. This is
not release acceptance, native SCM execution, host recovery, reboot, or soak proof.

## Watchdog

- Windows service chain integrated at `aa8adca`; independent P35 review approved
  source ownership, command binding, and durable-stop witness lifetime.
- Root ran locked/offline workspace tests with all targets/features, strict
  Clippy, and formatting successfully after integration. The idle-loop audit
  retention regression passed after more than 4,096 durable reconciliations.
- Candidate-to-manifest binding integrated at `d41fb03`; focused release tests
  passed. P36 approved that narrow binding, not the complete installer trust path.
- Held SCM-handle repair integrated at `382fd28`, from independently reviewed
  `09a6271e7c2a6f425c0f933523b0dc825e7afbcf`. Stop and deletion use one service
  object handle. Root Windows-target strict Clippy passed on the patch; independent
  review also cross-compiled platform tests. None of those binaries ran under SCM.
- Concurrent reconfiguration of the same SCM object and installer path/ACL,
  independent approval, and hash-to-execution guarantees remain separate work.

## Gateway

- Host-lease consumer and deadline repair integrated at `c63750e`, from reviewed
  candidate `2ce6b8086434677a5f1fa0b99085df92aae8575c` and its dependency chain.
- G53 independently parsed all three published request fixtures through the real
  decoder and checked canonical SHA-256 grant digests, expired-lease retry
  rejection, and late revoke acknowledgment persistence without reactivation.
- Root full locked/offline workspace/all-target/all-feature tests and strict
  Clippy passed after integration.
- Combined test coverage exceeded one file-size limit. Commit `2e44bfa` only
  extracts the existing duplicate-catalog regression into its own module. After
  that extraction, 19 catalog tests, strict Clippy, formatting, and strict policy
  passed; policy counted 200 files with zero warnings/errors.

## Still incomplete

Managed journal required-field/revoke consistency repairs, protected-storage
admission, worker protocol freeze and real consumers, harness recovery context,
broker repair integration, native service campaigns, and live-host validation
are not proven complete by this checkpoint. No services were installed or
activated during this integration.

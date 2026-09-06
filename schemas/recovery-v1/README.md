# `watchdog-recovery-v1`

This directory contains the closed sideband recovery frame and conformance
fixtures. The frame is additive: it carries a frozen `runtime-v3-gameplay`
action as bounded canonical bytes and does not change that gameplay schema.

The installed artifact is identified by `manifest.json` and its exact
`frame.schema.json` SHA-256 digest. Consumers must verify that digest before
decoding frames. See `../../docs/recovery-contract.md` for endpoint ownership,
identity lifetimes, RCJ-1 canonicalization, durable ordering, and rejection
semantics.

`frame.schema.json` validates shape and bounds. Owner implementations must add
semantic tests for cross-field equality, exact digest checks, authorization,
monotonic state transitions, duplicate handling, and persistence/crash windows.

Artifact publication through `sts2-protocol` is intentionally not implicit. A
protocol owner must review and publish the exact artifact, then update every
consumer and reject mixed digests in one coordinated release.

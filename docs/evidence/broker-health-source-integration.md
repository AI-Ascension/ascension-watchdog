# Broker and health-consumer source integration

Classification: confirmed local source integration, not executable broker/runtime
integration, a companion release, or native-service evidence.

The broker checkpoint `dac8a950024d79568efb606714663cbc95e4a065` was applied to
the existing health-consumer branch based on
`2c066cb216db5107cdd9e8bb3d5902af5d73a806`. Twenty-one non-overlapping files
match the checkpoint's Git blobs exactly. The two overlapping manifests were
combined additively, retaining the health client's base64/getrandom/hmac edges
and adding only the local Linux descriptor crate and its already locked edges.
All 35 other previously dirty files retained their exact prior SHA-256 digests.
The preservation map and combined-manifest hashes are recorded in
`docs/orchestration/broker-health-source-integration-20260909.json`.

Locked offline metadata, formatting and diff checks passed. Combined full
workspace/all-target/all-feature tests and strict Clippy passed (exit 0):

```sh
CARGO_INCREMENTAL=0 cargo test --workspace --all-targets --all-features --locked --offline -j1
CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets --all-features --locked --offline -j1 -- -D warnings
```

Explicitly gated native tests remained ignored; they are not native passes.
Earlier standalone broker or health results are not combined-source results.

The same strict Clippy command with `--target x86_64-pc-windows-gnu` also
passed (exit 0). This is cross-target validation, not native Windows execution.

`cargo deny --locked check advisories licenses bans sources` passed (exit 0),
with duplicate-version warnings for `hashbrown` and `syn` under the existing
dependency policy.

Independent read-only review confirmed all 21 import blobs, all 35 preservation
hashes, the three combined manifests, locked metadata and the source-only status
claims; no integration blocker was found. The source checkpoint is identified
by the containing Git revision. An exact combined release build is still running;
it is not yet release-build or activation evidence.

## Executable integration still required

`RuntimeProcessManager` still constructs `LinuxProcessAdapter`. Its typed worker
and gateway-health bootstrap paths use the trusted helper and a final durable
admission reservation before target execution. The broker's four-field legacy
launch request cannot carry those frames or preserve that barrier by itself.
Source presence therefore does not select the broker or make its launches ready.

Implement explicit broker selection, receipt-backed process ownership and
recovery, a separately authenticated one-shot typed stdin transport, and the
equivalent final admission barrier. Keep secrets out of JSON, argv, environment
and ledgers; bind only approved nonce/frame digests to prepared launch intent.
Reconcile both owner-local ledgers when a response or launch outcome is unknown.
Do not substitute broker `launch` for the current adapter before these contracts
and their failure-path tests are wired. Native systemd, descriptor/bootstrap,
descendant cleanup, restart and reboot evidence remain separately gated.

The imported `linux-broker-lifecycle-repair.md` and its JSON record describe the
frozen standalone broker checkpoint. This document records its subsequent source
integration; neither record claims completion of the full runtime assignment.

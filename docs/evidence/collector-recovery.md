# Collector synthetic recovery evidence

Classification: confirmed synthetic container/process-replacement evidence.
Not a live telemetry-plane deployment, backend durability, OS reboot, or soak.

Companion repository: `AI-Ascension/ai-agent-observability`.
Validated source: `b3a9fa64f51aa249f387190ce76df8c80a02af4b`.
Draft, unmerged delivery: <https://github.com/AI-Ascension/ai-agent-observability/pull/10>.
Exact-head CI: <https://github.com/AI-Ascension/ai-agent-observability/actions/runs/34074075350>.

The CI job completed successfully and its actual logs show:

1. The real Collector image accepted the production configuration.
2. With the synthetic sink absent, the fixture's eight-request persistent queue
   accumulated a marker and received 32 additional overflow spans.
3. A positive failed-enqueue counter proved explicit overflow/drop accounting.
4. The source Collector was forcibly killed and removed, then replaced using
   the same isolated storage volume.
5. A delayed sink received the original marker, distinct from overflow spans.

Tests execute real Docker containers on the hosted Linux CI runner, within an
internal isolated network. They remove only their uniquely named synthetic
containers, network, and volume. No game/provider processes or deployment
volumes are involved. The test probes were moved inside this network after
host-port lookup failed; production loopback bindings were not broadened.

Observed image digests in the preceding exact-image validation run:

- Collector 0.160.0: `sha256:799dc6cf12c96192af37b5bdba804da8c10b3bc563b43cb90c3f3c58d9572ad6`
- Alpine 3.22.1: `sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1`

The companion uses explicit image tags, not immutable digest pins; the observed
digests above are evidence, not an activated or reproducible release set.
MLflow/Laminar backend persistence, all stateful-store backup/restore, filesystem
quota behavior, native deployment recovery and long-duration bounds remain
unverified. The test proves process replacement, not power-loss durability.

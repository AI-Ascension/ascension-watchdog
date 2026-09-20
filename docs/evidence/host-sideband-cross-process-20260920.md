# Host sideband across two served processes — 2026-09-20

Classification: `confirmed` cross-process evidence from two locally built,
pin-recorded binaries, reproduced on live `main` of both repositories. It is
**not** soak evidence: `SOAK_VERIFIED` stays `unverified`, no soak window was
authorized, and no clock was started.

This record answers one question that neither repository could answer alone.
[sts2-harness#362](https://github.com/AI-Ascension/sts2-harness/pull/362) proved
the downstream host sideband in-process, through the served-fixture terminal.
[sts2-gateway#81](https://github.com/AI-Ascension/sts2-gateway/pull/81) proved
the real gateway's recovery routes against the gateway's *own* host fake. Each
half was proven against the other half's imitation. Nothing yet showed the real
`sts2-gateway-runtime` process driving the real `synthetic_mod_server` process
over the recovery mux that the campaign actually composes.

It also answers the *negative* half, which is the part that matters for
trusting the positive: **the same request, against the same gateway process,
fails when the downstream's host connection is removed or misconfigured**. That
is the check that would pass even if the production connection were gone.

## Topology

- One real `sts2-gateway-runtime` process, spawned through the pinned runtime
  binary, listening on a loopback port.
- One real `synthetic_mod_server` process (harness test support), spawned with
  `--ignored --exact run_synthetic_downstream_until_terminated`, listening on
  its own loopback port and terminating `POST /api/v1/runtime/recovery`.
- The gateway is configured with `STS2_MOD_ADDR` pointing at that downstream, so
  the host hop under test is the production hop, not a fabricated one.
- The probe client speaks the recovery contract directly to the gateway over
  loopback with `Authorization: Bearer <recovery token>` and
  `x-sts2-recovery-capability`.

Both children are started with `env -i`, so no ambient `STS2_*` variable can
silently satisfy an assertion. The only inputs that differ between the three
runs below are the downstream's sideband variables.

## Pins

| component | revision | label |
|---|---|---|
| sts2-gateway `main` | `fb7e57c38a5b5732937023ee12a3e8a4af04cabe` | confirmed (live `main`; the run was also reproduced at its ancestor `60002e8e`, so the host-hop contract is unchanged across #83, #84 and #86) |
| sts2-harness `main` | `b2376778` (merge of [#362](https://github.com/AI-Ascension/sts2-harness/pull/362)); the binary was built at the reviewed head `9385ffca48f3ada52ad476c61592419e78cd68f8` | confirmed |
| recovery contract / schema digest | `watchdog-recovery-v1` / `fb934d3157485aaf6e13e6ebbb213ec8a14c7fc6f5eeebc06b7a22c1f0009217` | source-derived |
| host lease-control key | bytes `0x00..=0x1f`, written as 64 hex characters | source-derived |

Built on this machine with `cargo build --locked` (Rust 1.97.1, Linux x86_64):

```text
be56008b09b799d0125c5b8c65af899e6ab437e9a6eac989452be12db436f8c9  sts2-gateway-runtime (gateway fb7e57c3)
e4d8e36628e12f2b659525ab968f6f704ed7068e685053a6c85f419dd7d60ec9  synthetic_mod_server  (harness b2376778)
```

These digests are `confirmed` for the local build only. They are not
reproducible-build claims.

## Method

The probe is committed as
[`deploy/soak/host-sideband-gateway-probe.sh`](../../deploy/soak/host-sideband-gateway-probe.sh).
It needs both binaries from the pins above and takes a mode:

```text
sh deploy/soak/host-sideband-gateway-probe.sh \
    --gateway-bin <sts2-gateway-runtime> \
    --mod-bin <synthetic_mod_server> \
    --mode configured
```

`configured` starts the downstream with `STS2_SYNTHETIC_HOST_LEASE_KEY` and
`STS2_SYNTHETIC_HOST_PRINCIPAL_ID`; `wrong-key` starts it with a key of the same
shape but different bytes; `closed` starts it with no key at all. The gateway's
own environment is identical in all three runs.

Each run then performs three steps: `POST /v1/recovery/bootstrap`, then
`POST /v1/recovery/host-fence` with the boot the served gateway returned, then
`POST /v1/recovery/lease/acquire` with that boot marked `READY` and the fence.

## Results

| mode | downstream readiness | bootstrap | host-fence | lease-acquire |
|---|---|---|---|---|
| `configured` | `host_lease=enabled` | `200` `BOOT_AUTHORITY_CREATED` | `200` `FENCE_ACCEPTED` | `200` `LEASE_ACTIVE` |
| `wrong-key` | `host_lease=enabled` | `200` `BOOT_AUTHORITY_CREATED` | `200` `FENCE_ACCEPTED` | `503` `recovery_host_lease_outcome_unknown` |
| `closed` | `host_lease=closed` | `200` `BOOT_AUTHORITY_CREATED` | `500` `fixture_invalid_request` | not reached |

## What each row establishes

`configured` is the positive: the served gateway completed bootstrap, fenced
the boot through the served downstream, and installed a lease. The probe also
asserts that the acknowledgment's `deployment_id`, `instance_id`,
`instance_incarnation`, `boot_id` and `authority_generation` are equal to the
boot the gateway itself presented, so the fence is bound to the served
identity and not merely well-formed.

`wrong-key` is the proof-carrying negative. The mux is open and the fence still
succeeds — that hop validates the fence body rather than an HMAC — but the lease
install fails with `503 recovery_host_lease_outcome_unknown`. The gateway signs
the install request with the host lease key; the downstream verifies the
inbound proof with *its* key, cannot reproduce it, and refuses the frame
(`host_lease_control_canonical.rs::verify_frame_proof`). The gateway never
receives an acknowledgment, so it reports the install as unconfirmed rather than
inventing a result. A key that only *exists* is therefore not enough: the shared
secret is load-bearing in both directions.

`closed` is the connection-removal control. The downstream answers the recovery
mux with the harness fixture's refusal, which the gateway relays verbatim as
`500 fixture_invalid_request`, and the fence is never accepted. If the
production host hop were removed from the downstream — or never wired — this is
the result, and only this row's expectation is a failure.

## What this does and does not prove

Proven: the merged harness downstream terminates the production host hop for a
served gateway, over real loopback sockets, with the pinned contract, digest,
identity and key; and the gateway refuses that hop when the downstream is not
configured for it.

Not proven, and not claimed here: any soak window; `SOAK_VERIFIED`; any
authorized two-episode single-deployment run (AC3–AC5 of
[ascension-watchdog#58](https://github.com/AI-Ascension/ascension-watchdog/issues/58)
remain open); the gateway's `watchdog-recovery-v1` recovery-fence path
(`POST /v1/recovery/host-fence` is exercised, recovery frames themselves are
not); lease renewal across a thirty-second boundary; any native game, provider
or deployment. Both processes run on one host as synthetic children, which the
objective authorizes.

This document does not complete #58.

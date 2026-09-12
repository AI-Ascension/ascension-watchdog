# Native on-host release activation and rollback — 2026-09-11

Classification: `native authenticated release activation/rollback against a
root-owned staged six-role release set on the supplied Train host`. It is not
cold boot, Windows SCM, WSL, live-host gameplay, or soak.

## What was exercised

A genuine six-role release set was built from the admitted current-main pins,
staged read-only under a root-owned catalog, and inspected/activated/rolled back
through the watchdog's authenticated admin channel while the daemon remained
reachable in `stopped` mode.

- Catalog root `/opt/ascension-watchdog/releases` (`0555 root:root`); release
  directories `native-activation-20260912-a` and `-b` (`0555 root:root`, roles
  `0555`, manifest `0444`).
- Config: `desired_mode=stopped`, no components, authenticated admin endpoint,
  `release_catalog { root, owner_uid: 0 }`.
- Daemon: user-scope `systemd-run --user` unit, `Type=notify`; reached
  `active/running` while `desired_mode=stopped`, so the admin path stayed
  available for a stopped deployment.

## Release set (built from the admitted pins)

| Role | Path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `watchdog` | `watchdog` | 6107536 | `ff34fca397628fca5aa4e8b0bb5066c96fc249ed7a99063378a067da6ff87ced` |
| `gateway` | `gateway` | 10849928 | `ae662c2d3e4c311e029bb123c2312959d57de9bc44aff2dfc2e4abc8ef491ab4` |
| `harness` | `harness` | 7280152 | `245452b193463bff62573639adb59d66a8a5506508f29d22f722353a19fd8986` |
| `mcp` | `mcp` | 2283208 | `712ee2ae518d3ba0ba21b9f21f94f9cd76317af79c60d6b14b7ce11dd5648174` |
| `mod` | `mod` | 655616 | `ace303173e13390294157d3b3f147d93b6896acf84f89dd0caa3bc431a0142b0` |
| `host_broker` | `host-broker` | 3520136 | `bae5044b85423b87d5938883ea9bd69e3e633b983a2118f52d5ba6f32a99c7ad` |

Revisions bind `ascension-watchdog` `20348c69006974eaab96d55491d540c85dc87289`,
`sts2-gateway` `8940fba823a0893b31d1a96301831c182d37ed32`, `sts2-harness`
`4584c4cbc2f6bcb900f99092cafa80d32ca0cce8`, `sts2-mcp-server`
`f3b6eaa8bcf2241b8d6c47587c958388a8fe1031`, `sts2-game-mod`
`afa44d6f8da66625b67a10d758725da01492a27a`, and `sts2-protocol`
`219510c4d4f9c96a54f510cca085a48a92bfe490`.

Compatibility uses the fixed profiles (`runtime-v3-gameplay`,
`watchdog-recovery-v1`), real protocol-artifact digests for the runtime/recovery
/provider digests, all three owner store ranges, and
`configuration_sha256 = c390c90166eef35f567d357f22e3f6b0c8a42f9864cff7e479ab209fd1b5e3c3`
(the exact deployment config digest).

## Observed sequence

| Step | Result |
| --- | --- |
| `release inspect --release-id ...-a` | `status=OK`; `release_digest=f3e71ecc3b4ee9628b7228c32069fd4d751ae5ec058f249886c14a152e392d2e`, `compatible=true`, `active=true` |
| `release activate ...-a` | `OK`; selector `active=...-a` |
| `release activate ...-b` | `OK`; selector `active=...-b`, `previous=...-a` |
| `release rollback ...-a` | `OK`; selector `active=...-a`, `previous=...-b` |

The expected digests were the SHA-256 of each release's exact manifest bytes
(`f3e71ecc…` for `-a`, `8e67d1b9fb046a544c6525d89eb23a3c73ed80d747dcd6e63040c8d32f2ab37f`
for `-b`), so a matching activation proves the manifest-byte binding, the
protected catalog inspection, and the configuration-digest compatibility gate.

## Honest limitation

The two releases share identical artifact bytes and differ only in release
identity/manifest bytes. This exercises the selector, digest binding, and
rollback to the exact previous identity; it is not a test of two distinct
product builds.

## Boundary

Verified: authenticated on-host `release inspect`, `activate`, and `rollback`
over a root-owned staged six-role set with profile/store/config compatibility
and exact manifest-digest binding. Not verified: cold boot, Windows SCM, WSL,
live-host gameplay recovery, or the 24-hour soak.

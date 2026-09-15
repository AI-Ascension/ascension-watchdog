# Native Linux service and VM reboot qualification — 2026-09-15

Classification: **native systemd supervisor lifecycle and guest reboot**, with
synthetic child processes. This is not an admitted companion release, Windows
SCM qualification, live gameplay recovery, physical-host cold boot, or continuous
deployment soak. Issue #1 remains open.

## Artifact and environment

- Watchdog source: `d69a5087922374b492d311fab0b05866e6b99c63`.
- Build: `cargo build --release --locked -p ascension-watchdog --bin watchdog`,
  Rust `1.97.1`, Linux x86-64.
- Binary SHA-256:
  `32452b39dbaee95636a501448fe349db0d305a58fe987b3196d8173673951610`.
- Dedicated KVM guest: Ubuntu Minimal 24.04.4, 2 vCPUs, 2 GiB RAM, 12 GiB virtual
  disk. The Ubuntu image was verified against signed checksum metadata.
- Domain UUID: `b7a57291-1d83-41b7-9a0f-485602b34e60`.
- The shipped `deploy/linux/install.sh` and `ascension-watchdog.service` were
  used. Service settings include `Type=notify`, `WatchdogSec=30s`,
  `Restart=on-failure`, and `KillMode=control-group`.

The operator authorized a dedicated VM, VM reboots, and service restarts.
Physical-host reboot still requires separate confirmation and was not performed.
The host boot ID remained `c7fd10ce-867d-4661-a51d-8a641c65637d`.

## Measured scenarios

The two scenarios use separate owner-local databases and configuration identities.
The first scenario's uncertain state was retained when preparing the second.
The [receipt directory](native-vm-qualification-20260915/) contains the measured
command outputs, both configurations, packaging metadata, a machine-readable
summary, and `SHA256SUMS`. The initial host boot ID is a transcription of the
provisioner's tool output; the final host observation is a saved raw receipt.

| Check | Observed result |
| --- | --- |
| Ready baseline | Service PID `1789`, `NRestarts=0`, authenticated `ready=true`, desired mode `running`; synthetic sleep child PID `1799`. |
| Supervisor crash | After SIGKILL, systemd restarted the supervisor as PID `1877`, `NRestarts=1`. It was ready with phase `blocked`; the prior child identity was quarantined, and no matching sleep process remained. |
| Guest reboot with uncertainty | Boot ID changed from `7c504db1-a01b-457c-a406-55a735ff2f87` to `eaed5e5e-7565-4a13-a6ff-446b570d8ce4`. The service started automatically as PID `463`, ready with desired mode `running`. The same quarantined nonce and PID record remained, with zero matching child processes. |
| Separate active-child stop | A fresh deployment supervised sleep child PID `744`. Authenticated stop returned `ACCEPTED`; the child count fell from one to zero and the component became `stopped`. |
| Guest reboot after durable stop | Boot ID changed to `451ea625-b4b4-4803-9ace-b069fc9497f9`. Service PID `462` was active and ready, desired mode and phase were `stopped`, and no matching child revived. The first scenario's quarantine record remained readable separately. |

The crash result is conservative uncertainty retention, not successful
reconstruction or autonomous child recovery. The sleep processes do not represent
gateway, harness, game, or provider behavior.
The separate stop scenario's component row was `suspect` at its baseline, while
the matching process count was one. This proves stopping a live child, not a
healthy-component baseline or prolonged absence of revival.

## Configuration and setup boundaries

Scenario one used deployment `vm-qualification-20260915` and semantic config
digest `7df8c1d069ee045aab13debd811cf6267eb059d6618885ce56c96eea63edec92`.
Scenario two used deployment `vm-durable-stop-20260915` and semantic config
digest `bc39c6f980da23cc6baa09aaaaa453cd0a7d423c930ee7931fb89691c7fd59d9`.
These are supervisor-only fixtures; authenticated status reported
`approved_release_digest=null`.

Before the measured baseline, setup required an executable mode readable by the
service account, explicit database initialization, and a private `0700` directory
for the authenticated admin socket. Those setup failures are not recovery passes.
Credential files were owned by the service account with mode `0600`; credential
contents are excluded from evidence.

The guest remains available for inspection with the watchdog service running in
durably stopped mode and no synthetic child running. Domain autostart on the
physical host is disabled. A guest reboot does not demonstrate physical-host
reboot or domain autostart.

## Remaining acceptance

This refreshes native Linux supervisor/service and VM reboot evidence for the
specified watchdog revision. It does not update historical multi-repository
admission pins or make that release ready. Installed Windows service lifecycle,
integrated live-host recovery, physical-host boot behavior, distinct-build
activation/rollback, and continuous single-deployment soak still need their own
evidence. Repeated composition and elapsed duration alone do not satisfy soak.

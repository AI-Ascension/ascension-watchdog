# VM-level cold boot evidence — 2026-09-12

Classification: `VM-level cold boot` on a disposable libvirt guest provisioned
from the official Ubuntu cloud image. The shared Train host was **not** rebooted
(explicit constraint). This is not Windows SCM, WSL, live-host gameplay, or the
cross-repo soak.

## Provisioning

- Base image: official Ubuntu 24.04 `noble-server-cloudimg-amd64.img`
  (downloaded from `cloud-images.ubuntu.com`, 625 MB).
- Cloud-init seed (`xorriso`, volume label `CIDATA`) created a `codex` user with
  an injected ed25519 key and `NOPASSWD` sudo; the guest booted on the existing
  libvirt `default` network.
- Overlay disk: `qemu-img create -b noble.img -F qcow2 -o size=12G`, attached
  with the seed ISO as a CD-ROM via `virt-install --import`.
- Guest: kernel `6.8.0-139-generic`, systemd running, `cloud-init status: done`,
  reachable at `192.168.122.190`.

The shipped release and unit were installed inside the guest exactly as the
host install (`install.sh`), with an authenticated admin endpoint and a
synthetic component (`/bin/sleep 987661`, `restart=true`). The service reached
`active/running` with the child supervised.

## Observed sequence

| Step | Action | Result |
| --- | --- | --- |
| install | `install.sh` in guest | unit enabled; `Type=notify`, `NotifyAccess=main`, `User=ascension-watchdog`, `KillMode=control-group`, `Restart=on-failure`; service `active`, child count 1 |
| cold boot 1 | `systemctl reboot` | guest `up 0 minutes`; `systemctl is-system-running=running`; the enabled unit auto-started to `active (running)` |
| durable stop | authenticated `stop` as the service account | accepted; child count 1 → 0 |
| cold boot 2 | `systemctl reboot` | guest rebooted; the enabled unit auto-started; `desired_mode=stopped` persisted; child count 0 (no revival) |
| retained uncertainty | component record | quarantined with `owned child handle unavailable; exact orphan identity retained` |

So a real VM reboot restarts the enabled system service into a ready supervisor,
and a durable stopped intent survives the reboot without reviving the component.
The unreconstructable synthetic intent is retained as a quarantined orphan
rather than relaunched.

## Cleanup

The domain was destroyed and undefined with its storage, and the cloud
image/seed/overlay/key directory was removed; no domain, lease, or artifact from
this test remains. The host was not rebooted.

## Boundary

Verified: VM-level cold boot of the supported systemd service, boot-time
readiness, durable-stop survival across a reboot, and conservative retention of
an unreconstructable intent. Not verified: host-level reboot (disallowed),
Windows SCM, WSL, live-host gameplay, or the cross-repo soak.

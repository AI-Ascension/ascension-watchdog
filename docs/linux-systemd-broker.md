# Linux systemd launch broker

The optional Linux broker is a root-owned systemd service for deployments that
need a distinct OS identity per supervised component. The existing
LinuxProcessAdapter remains a same-UID delegated-cgroup adapter and is not
silently upgraded by this package.

The broker socket accepts exactly four request fields:

    {"component":"gateway","instance":"instance-a","incarnation":"boot-7","nonce":"launch-9"}

Paths, arguments, environment, target users, capabilities and cgroup names
cannot be supplied by a client. A protected JSON policy maps each component to
an executable and SHA-256 digest, fixed arguments and working directory,
minimal environment, distinct non-root UID/GID, zero capability sets,
NoNewPrivileges, Delegate=no, KillMode=control-group, and bounded cgroup
resources and timeouts.

The service authenticates SO_PEERCRED UID/GID and hashes the exact peer
executable from /proc/<pid>/exe. It uses the native system D-Bus API
org.freedesktop.systemd1.Manager.StartTransientUnit; it never invokes
systemd-run, a shell, or a generic command runner. The broker hashes the
approved target again immediately before the D-Bus effect.

The acknowledgement is issued only after the exact generated unit is active
and its MainPID has a captured /proc start token, the requested UID/GID,
empty supplementary groups, the expected capability bounding and ambient
sets, NoNewPrivileges, and an exact unified-cgroup path equal to systemd's
ControlGroup. A repeated component/instance/incarnation/nonce maps to the
same unit name and cannot start a second unit. Cleanup addresses only that
generated unit.

deploy/linux/systemd-broker-policy.example.json is a shape-only example:
replace every digest and install the policy as a root-owned, non-group-writable
file. The native broker test is intentionally ignored until an approved
disposable Linux host provides PID 1/system D-Bus and distinct service users.
Portable fake-backend tests prove request closure, peer admission,
postcondition checks and duplicate idempotence, but do not prove native
systemd enforcement.

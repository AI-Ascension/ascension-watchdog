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
empty supplementary groups, the expected zero capability bounding and ambient
sets, NoNewPrivileges, and an exact unified-cgroup path equal to systemd's
ControlGroup. A repeated component/instance/incarnation/nonce maps to the
same unit name and cannot start a second unit. Cleanup addresses only that
generated unit.

The broker writes a root-owned append-only idempotence ledger before calling
StartTransientUnit and syncs the record. A pending or committed record whose
unit is inactive is an uncertainty/conflict, never permission to relaunch an
old nonce. The transient unit has `BindsTo=ascension-watchdog-broker.service`,
so broker owner death causes PID 1 to stop the target. Broker I/O, D-Bus calls,
hashing, receipt retention and active units are bounded.

`deploy/linux/install-systemd-broker.sh` installs the binary, root-owned policy,
unit and peer-group-compatible socket setup after checking that the policy's
peer GID matches an existing group. It reloads systemd but does not enable or
start the service.

deploy/linux/systemd-broker-policy.example.json is a shape-only example:
replace every digest and install the policy as a root-owned, non-group-writable
file. The watchdog's existing LinuxProcessAdapter is not wired to this client
by this package; its production integration remains an explicit caller-owned
seam. The native broker test is intentionally ignored until an approved
disposable Linux host provides PID 1/system D-Bus and distinct service users.
Portable fake-backend tests prove request closure, peer admission,
postcondition checks and duplicate idempotence, but do not prove native
systemd enforcement.

The ignored native recipe sets `ASCENSION_NATIVE_BROKER_TEST=1`, points
`ASCENSION_NATIVE_BROKER_SOCKET` at the installed socket, and supplies an
operator-approved cleanup helper through
`ASCENSION_NATIVE_BROKER_CLEANUP_HELPER`. The test then launches through
`BrokerClient`, correlates the receipt to `/proc`, invokes the exact-unit
cleanup helper, and waits for the process to disappear. It is not run by CI or
by this source-only package.

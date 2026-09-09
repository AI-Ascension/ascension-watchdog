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
and its MainPID has a captured kernel-boot-UUID plus /proc start-tick token, the requested UID/GID,
empty supplementary groups, the expected zero capability bounding and ambient
sets, NoNewPrivileges, and an exact unified-cgroup path equal to systemd's
ControlGroup. The original cgroup directory must also be positively verified in
PID 1's descriptor store before the durable launch receipt is acknowledged.
A repeated component/instance/incarnation/nonce maps to the
same unit name and cannot start a second unit. Cleanup addresses only that
generated unit.

The broker's opaque creation token is `boot:<canonical-uuid>:<start-ticks>`.
This prevents the same PID and start tick on a different boot from matching a
durable receipt. Bare legacy tick tokens remain historical data and cannot
match a new native observation; they are not silently upgraded. Worker-IPC
decimal creation tokens are a separate contract and are unchanged. This uses
the kernel's [boot identity](https://www.kernel.org/doc/html/v6.9/admin-guide/sysctl/kernel.html#random),
not an application-restored counter. It does not by itself prove reboot recovery.

The broker writes a root-owned append-only idempotence ledger before calling
StartTransientUnit and syncs the record. A pending or committed record whose
unit is inactive is an uncertainty/conflict, never permission to relaunch an
old nonce. The transient unit has `BindsTo=ascension-watchdog-broker.service`,
so broker owner death causes PID 1 to stop the target. Broker I/O, D-Bus calls,
hashing, receipt retention and active units are bounded.

Lifecycle inspection and stop use a separate versioned envelope:

    {"version":1,"operation":"inspect","request":{"component":"gateway","instance":"instance-a","incarnation":"boot-7","nonce":"launch-9"}}

`operation` is either `inspect` or `stop`; the nested request is still the
complete identity and is the only unit selector. Both operations authenticate
the current peer and current fixed policy, then require a committed ledger
receipt and an exact live PID/start-token/executable/credential/capability/
cgroup match. Inspection never writes the ledger. Stop commits a durable
`stoppending` record before effects. It holds no-follow cgroup-v2 control
descriptors, verifies the original leader in that containment, requests graceful
termination through a bound pidfd, and uses the held `cgroup.kill` descriptor if
the graceful interval expires. The held `cgroup.events` population witness must
be empty before the backend reports success and the broker appends the durable
terminal `stopped` record. A unit-name or ordinary systemd object-path stop is
not used: neither binds an immutable containment through a replacement race.
A stop timeout, backend error, changed
identity, or failed terminal append retains active ownership and leaves the
record retryable/uncertain; it never falls back to a PID, process name, or
caller-supplied unit. Repeated stop requests for a verified terminal record
are idempotent and never repeat termination; they may finish exact descriptor
cleanup left incomplete after durable retirement. Pending, unknown, orphaned, and
unproven inactive requests fail closed.

Initial cgroup capability capture occurs only for a newly reserved, freshly
started, policy-verified process before launch acknowledgement. Duplicate launch
requires both the retained original capability and positive manager-store proof;
active stop requires the retained original capability. Neither can
reopen a pathname after losing it. A replacement owner may recover controls
relative to an authenticated, inherited original directory descriptor only.
Retained descriptors are bounded by the 128 receipt limit.
A process-local verified-empty fact survives a later removal of
the cgroup files, but an error before that fact is obtained remains unknown.

Natural exit can be retired by an authenticated stop request when the same
broker still holds the original capability and reads its empty population.
This appends stop intent and terminal state without a termination effect.
Interrupted stop likewise requires the original empty witness; `NoSuchUnit`,
inactive state, or backend stop success alone cannot authorize terminal state.
Inspection remains read-only and does not perform this retirement.

The packaged native stop path requires a root-managed cgroup-v2 hierarchy at
`/sys/fs/cgroup`. It rejects symlinks, other filesystems, and group/other-writable
controls rather than choosing an alternate path. The ledger permits 128 distinct
requests with four lifecycle records each; its 8,389,120-byte reopen bound covers
512 maximum-size records including newlines. Appends exceeding the aggregate
bound fail before writing. Later lifecycle receipts must retain the complete
previous process binding.

The 64-process admission limit counts every durable pending, committed, and
stop-pending request, including records reopened by a replacement owner.
Only verified terminal retirement frees a slot; the old nonce stays reserved.
An exact duplicate already occupying an in-memory slot consumes no extra slot.

The packaged broker needs `CAP_SYS_PTRACE` for cross-UID
[/proc executable checks](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html)
and `CAP_KILL` for [cross-UID signalling](https://man7.org/linux/man-pages/man2/kill.2.html).
These are scoped service-package capabilities, not capabilities granted to
supervised components. `NoNewPrivileges` and the zero ambient set remain in
place. The package has not been installed or natively validated by these tests.

The broker package explicitly limits systemd to five starts per 600-second
interval, including the initial/manual start, with two seconds between automatic
failure retries. `StartLimitAction=none` cannot request a host reboot. Exhausting
the limit stops automatic recovery; diagnose the failure before an authorized
manual restart. Do not automatically invoke `reset-failed` to bypass the limit.
This manager-owned limiter is separate from persistent deployment/attempt retry
budgets: manager counters may be cleared by unit unloading or administrative
reset and do not provide durable cross-boot accounting. See
[systemd start-rate semantics](https://github.com/systemd/systemd/blob/v257/man/systemd.unit.xml#L1059-L1104).

## Descriptor preservation and startup intake

The packaged broker requires systemd v254 or newer, the protected system bus at
`/run/dbus/system_bus_socket`, and `NOTIFY_SOCKET=/run/systemd/notify`.
Environment-selected bus addresses, user managers and alternate notification
endpoints are not admitted. Preflight authenticates the system manager as root
PID 1 and verifies that this process is the exact broker unit's MainPID, with
`NotifyAccess=main`, `FileDescriptorStoreMax=128`, and
`FileDescriptorStorePreserve=yes`. Unsupported properties or a missing descriptor
snapshot API block startup before launch effects.

Each descriptor name hashes the complete receipt, excluding its transport-only
duplicate flag. The broker sends one directory using SCM_RIGHTS with `FDSTORE=1`
and `FDPOLL=0`, then sends a separate one-fd `BARRIER=1`. A processed barrier is
not evidence that storage succeeded. The broker queries
`DumpUnitFileDescriptorStore` and matches the exact name, mode, device/inode,
device-node identity and status flags while still holding the original directory.
The bounded snapshot is the state-level linearization point: an earlier retained
copy of the same object is an idempotent success, not proof that this particular
notification inserted a new descriptor. Snapshot paths are diagnostic, never
opened as authority. See the [systemd descriptor-store API implementation](https://github.com/systemd/systemd/blob/v257/src/core/dbus-service.c#L213-L271)
and [FDSTORE/barrier semantics](https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html).

Startup captures inherited descriptors before loading policy/ledger files,
opening sockets, or creating D-Bus threads. `LISTEN_PID`, `LISTEN_FDS`, and
`LISTEN_FDNAMES` must form a complete, bounded, canonical set with unique names.
When present, `LISTEN_PIDFDID` must match the current process's verified pidfs
identity; unsupported or ambiguous identity fails closed. The isolated
`ascension-platform-linux-descriptors` crate duplicates each raw descriptor above
the entire activation range and gives only that fresh copy Rust ownership.
Both copy and original are CLOEXEC; at most 128 unowned originals remain open
until broker exit. A later-copy failure drops earlier owned copies and aborts.
The workspace and portable watchdog retain `unsafe_code=forbid`; only this
crate's annotated duplication function permits native calls. Its ownership
contract follows [F_DUPFD_CLOEXEC](https://man7.org/linux/man-pages/man2/F_DUPFD.2const.html)
and [OwnedFd construction](https://doc.rust-lang.org/std/os/fd/trait.FromRawFd.html).

Before using an inherited directory, the broker matches every entry against the
authenticated manager snapshot and verifies cgroup-v2 filesystem, directory type,
root ownership and protected permissions. Only a policy-compatible committed or
stop-pending durable receipt can bind recovered controls. Controls are opened via
`openat` on that original directory, never a reconstructed unit pathname.
Unmatched or unreadable original directories are retained within the same bound
but grant no process authority.

After verified emptiness and a synced terminal `stopped` record, authenticated
stop first verifies any stored same-name descriptor against the original held
object, then removes only that receipt's descriptor name. A different same-name
object is a conflict, not removal authority. A separate barrier and snapshot
must prove its absence before the local copy is released. Failure leaves the
durable terminal record intact; retry performs cleanup without a second kill.
Read-only inspection never submits FDSTOREREMOVE. Unresolved records keep their
capabilities and cannot free capacity by dropping evidence.

A descriptor transfer or launch-receipt commit can fail after the process has
started and its original controls have been verified. Local capture is retained
even when manager-store verification fails, but cannot acknowledge a launch.
Failed-launch cleanup verifies this local original, syncs an exact
`pending -> stoppending` receipt, performs bounded cleanup, verifies emptiness,
syncs `stopped`, and removes the descriptor. This three-record path fits the
existing four-record-per-request bound; it never claims a committed launch.
Interrupted cleanup keeps the exact receipt available for recovery. If the
cleanup intent cannot be persisted, no termination or descriptor removal occurs;
poisoned persistence blocks the entire cleanup path.

When systemd reports a missing/inactive unit or zero MainPID, an authenticated
Stop can now clean up surviving descendants using the retained original group.
Only the exact typed `org.freedesktop.systemd1.NoSuchUnit` method error means
absence; generic error text, process-read failures and changed live identity
cannot enter this path. Inspect remains read-only and reports uncertainty.

The broker first reads the original population witness. Already-empty groups
need no kill. A readable populated group requires the exact durable receipt,
current policy and retained original controls, then a synced stop-pending record.
It allows a bounded drain interval before writing the held `cgroup.kill`, without
looking up a leader PID, unit object or replacement pathname. A positive original
empty witness is required before the terminal append and descriptor removal.
Read errors are not population evidence and do not authorize this fallback;
timeouts after the kill retain stop intent and the original capability.
The population and force-stop contract follows the
[kernel cgroup-v2 interface](https://github.com/torvalds/linux/blob/v6.12/Documentation/admin-guide/cgroup-v2.rst#L858-L941).
File-replacement tests exercise the actual native backend with ordinary control
files, not native cgroup enforcement. Native descendant/restart validation remains
gated. If the leader dies during an already-started live-stop check, that check
can still fail; a retry of the same durable stop can use this orphan path after
systemd reports the inactive/leaderless state.

Recovery availability remains incomplete: if cgroup controls become unreadable
before an empty witness was obtained, their original directory is preserved but
retirement remains unproven. `BindsTo` teardown can produce this case during
broker death. Neither ENODEV, ENOENT, a deleted-path annotation nor NoSuchUnit is
promoted to an empty witness. Verified boot-boundary retirement is also unfinished.
These cases remain conflicts rather than being silently forgotten.
Portable pathname-replacement fixtures exercise retained file identity but are
not evidence of native cgroup enforcement or installed-service recovery.

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

# Linux broker lifecycle integration review

Classification: source-derived review of an in-progress, unintegrated change.
This is not a passing native systemd test or approval to enable broker launches.

The lifecycle implementation adds authenticated inspect/stop requests and a
durable stop-pending transition. Root review identified these remaining checks
before integration:

1. **Stop must bind the original containment through the effect.** Looking up a
   systemd unit, validating PID/birth/cgroup, and then invoking `Unit.Stop` on
   its ordinary object path leaves a replacement interval. The ordinary path is
   derived from the unit name, not an immutable incarnation. Upstream
   [systemd unit source](https://github.com/systemd/systemd/blob/main/src/core/unit.c)
   implements `unit_dbus_path` through `unit_dbus_path_from_name(u->id)`.
   A held cgroup directory/control capability must retain the original object
   through termination and empty-state verification, or an alternative must
   supply equivalent versioned, executable evidence. A changed pathname must
   not redirect termination to replacement processes.

2. **Admission must preserve enough ledger capacity for every lifecycle
   transition.** A bound of 128 requests and four transitions each permits 512
   records. With records bounded individually at 16 KiB, that can exceed the
   1 MiB reopen limit. Successful append must not produce a ledger the next
   owner rejects as oversized. Test large legal records and near-capacity
   reopen/stop sequences, not only many small records. Backpressure before a
   launch must preserve existing requests' ability to record stop uncertainty.

3. **Direct adapter paths are not a substitute for a held capability.** The
   existing direct adapter's `Cgroup` stores a pathname and opens `cgroup.kill`
   by that name at effect time. Reusing that implementation does not resolve
   the lifecycle replacement interval or the separate same-credential escape
   concern. Runtime broker adoption remains incomplete.

The author has these findings for repair. Passing health-consumer tests, native
Windows bootstrap tests, and the watchdog release build do not cover this
unintegrated broker change. A fresh independent review and root regression run
are required after the repaired source is frozen.

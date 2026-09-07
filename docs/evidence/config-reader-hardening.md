# Bounded configuration reader validation

Code: `92b4cdebcc0da04b69627001ce5ca675ef74ba46`; Windows import correction:
`9c983b5`. Classification: confirmed Linux tests and Windows cross-target lint,
not native Windows installation or service evidence.

Before the repair, an actual CLI subprocess blocked opening a FIFO configuration;
the regression's two-second deadline killed and reaped that exact child. The
repaired reader walks Unix path components using nonblocking no-follow handles,
rejects non-regular leaves, and reads at most 65,536 bytes. The normalized source
path remains compatible with the separately protected Linux bootstrap reader.
The oversize error retains the existing `65536-byte limit` compatibility text.

Root validation on the integrated tree passed:

```sh
cargo fmt --all --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo clippy --locked --workspace --all-targets --all-features --target x86_64-pc-windows-gnu -- -D warnings
```

The full Linux run includes the three new configuration-reader regressions and
51 fault-fixture tests. Two native/cgroup tests remain ignored, not passed.
The first Windows cross-target lint run found an existing Unix-only `File`
import; `9c983b5` applies only the platform conditional import, after which the
cross-target lint command passed.

Independent P23 review reran configuration, Linux bootstrap path-replacement,
and protected configuration tests. Relative paths with `.` components work;
parent traversal and symlink ancestors are rejected. Non-Linux Unix behavior
was not executed.

## Windows provisioning limitation

The Windows reader uses the existing protected payload-file reader. It requires
current-user ownership and a non-inherited owner-only DACL. Ordinary inherited
ACL configuration files are rejected. `WatchdogConfig::to_file` does not provision
that ACL, and an operator-owned configuration is not automatically readable
under the virtual service account's owner requirement. Therefore cross-target
success does **not** establish usable Windows configuration installation.
Protected configuration provisioning and an explicit operator/service access
policy remain required deployment work; do not silently relax the reader.

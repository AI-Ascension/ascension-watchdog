# Windows SCM service wiring

Classification: source and cross-compilation evidence only. No Windows service
was installed, started, stopped, or removed in this validation, and no native
SCM, reboot, desktop-session, or live-host claim follows.

The watchdog executable now recognizes only the bounded service invocation
`daemon --service --config PATH`, where `PATH` is canonical, absolute, and
validated before dispatch. The entrypoint uses
`ascension-platform-windows::ServiceRuntime`; its readiness witness opens the
existing owner-local state and completes a real `ServiceLoop::reconcile`
before SCM receives `Running`. SCM stop is observed by the loop, persisted as
`Stopped`, and only then reconciled into exact child cleanup.

`watchdog service install` delegates to `ServiceInstallPlan`, while the Windows
PowerShell wrappers remain thin packaging helpers. Installation does not start
the service. The install wrapper requires a separate protected release verifier
and runs `release inspect --manifest ... --root ...` successfully before any SCM
mutation; a manifest's presence alone is not validation. Uninstallation first
queries SCM and requires the fixed service name, own-process/automatic-start
shape, canonical executable, and exact `daemon --service --config PATH`
binding. Only that concrete binding may receive the bounded stop and final
delete re-query; the owner-local store is opened after SCM stop and must reach
a clean `Stopped` reconciliation. A missing service is an idempotent no-op.
There is no data-removal switch: state, credentials, and releases are
preserved for separately audited lifecycle work.

The configuration file must also be provisioned with ACLs readable by the
installed service identity. This source-only review does not claim that an
operator-owned/inherited config is readable by the virtual service account.

Validation from the isolated service-wiring worktree:

```text
cargo fmt --all --check                                      # exit 0
cargo test --locked -p ascension-watchdog --lib              # exit 0; 53 passed, 1 ignored
cargo check --locked --target x86_64-pc-windows-gnu \
  -p ascension-watchdog                                       # exit 0
cargo clippy --locked --target x86_64-pc-windows-gnu \
  -p ascension-watchdog --all-targets -- -D warnings         # exit 0
cargo clippy --locked --target x86_64-pc-windows-gnu \
  -p ascension-platform-windows --all-targets -- -D warnings # exit 0
cargo test --locked --target x86_64-pc-windows-gnu \
  -p ascension-watchdog --all-targets --no-run                # exit 0
```

The Windows target binaries were compiled but not executed because this Linux
workstation is not an authorized native Windows SCM test host.

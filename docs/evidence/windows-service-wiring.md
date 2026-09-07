# Windows SCM service wiring

Classification: source and cross-compilation evidence only. No Windows service
was installed, started, stopped, or removed in this validation, and no native
SCM, reboot, desktop-session, or live-host claim follows.

The watchdog executable now recognizes only the bounded service invocation
`daemon --service`, optionally followed by one absolute `--config` path. The
entrypoint uses `ascension-platform-windows::ServiceRuntime`; its readiness
witness opens the existing owner-local state and completes a real
`ServiceLoop::reconcile` before SCM receives `Running`. SCM stop is observed by
the loop, persisted as `Stopped`, and only then reconciled into exact child
cleanup.

`watchdog service install` delegates to `ServiceInstallPlan`, while the Windows
PowerShell wrappers remain thin packaging helpers. Installation does not start
the service. Uninstallation preserves state and releases by default; data
removal requires an explicit switch and exact path.

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

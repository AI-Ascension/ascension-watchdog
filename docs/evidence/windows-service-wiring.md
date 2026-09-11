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
the service. The install wrapper requires a separately hashed release verifier,
rejects reparse points throughout the candidate release, and runs `release
inspect --manifest ... --root ...` successfully before any SCM mutation; a
manifest's presence alone is not validation. It then resets inherited/explicit
ACL entries and protects the release and config for SYSTEM/Administrators while
granting the fixed virtual service identity read-only access before registering
SCM. The config owner is set to SYSTEM so the service's protected config reader
and the operator's administrative read path agree on the same policy.
Uninstallation first verifies a non-reparse `watchdog.exe` against the
caller-supplied SHA-256, then queries SCM and requires the fixed service name,
own-process/automatic-start shape, canonical executable, and exact `daemon --service --config PATH`
binding. Only that concrete binding may receive the bounded stop and final
delete re-query; the owner-local store is opened after SCM stop and must reach
a clean `Stopped` reconciliation. A missing service is an idempotent no-op.
There is no data-removal switch: state, credentials, and releases are
preserved for separately audited lifecycle work.

The installer now contains the ACL provisioning boundary, but this source-only
review does not claim that Windows account-name resolution, native ACL access,
or SCM installation succeeded on a host.

The package preflight is also available as:

```text
pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File deploy/windows/test-install-uninstall.ps1 -RepositoryPath .
```

It parses both wrappers and verifies that mismatched verifier bytes and a
failed release inspection stop before SCM mutation. It creates only temporary
fixture files, removes them in a cleanup block, and performs no target service
or release installation.

The existing Windows workspace test lane invokes this preflight through
`crates/watchdog/tests/windows_packaging.rs`. That test is a deployment-script
gate only: it does not install, start, stop, or remove an SCM service.

The current Linux workspace validation for the packaging boundary is:

```text
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 test --locked -p ascension-watchdog \
  --all-targets --all-features -- --test-threads=1          # 212 passed, 4 ignored
cargo +1.97.1 clippy --workspace --all-targets --all-features \
  --locked -- -D warnings
cargo +1.97.1 check --locked --target x86_64-pc-windows-gnu \
  -p ascension-platform-windows --all-targets
cargo +1.97.1 clippy --locked --target x86_64-pc-windows-gnu \
  -p ascension-platform-windows --all-targets -- -D warnings
```

These commands pass locally. The full watchdog GNU-target check/no-run is not
claimed here because the bundled SQLite build requires MinGW `gcc`, which is
absent on this Linux workstation. Hosted Windows executes the complete
workspace lane, including the native ACL reader test and packaging preflight;
that evidence remains synthetic/native-hosted and does not claim SCM
installation or live service recovery.

# Windows CI repair evidence — 2026-09-09

Classification: source, cross-compilation, and native Windows synthetic evidence for the isolated
`codex/watchdog-windows-ci` worktree at base `868b214`. No service was
installed, started, stopped, or removed, and no host, reboot, desktop-session,
or gameplay claim follows.

The failed Windows job was
[`102288276011`](https://github.com/AI-Ascension/ascension-watchdog/actions/runs/34294570069/job/102288276011)
from run `34294570069`. Its two failures were:

- `native::tests::planned_job_recovery_rejects_an_unrelated_job_limit`:
  `IdentityMismatch("named Job Object owner differs from the current service token")`.
- `native::tests::service_binding_rejects_a_different_existing_config`: the
  owner/config binding assertion for manual and disabled start modes failed.

The Job Object and lifecycle-pipe descriptor now sets an explicit `O:<current
TokenUser SID>` owner and retains the protected owner-rights DACL
`D:P(A;;GA;;;OW)`. This preserves strict reopen-time owner validation while
avoiding the elevated-token default-owner (Administrators) mismatch. The SCM
fixture now renders canonical config paths, matching
`ServiceInstallPlan::install_as_with_config` before it hands the command line
to SCM; validation remains strict and still rejects the other config.

Checks completed in this worktree:

```text
cargo fmt --all --check                                      # exit 0
cargo check --locked --target x86_64-pc-windows-gnu \
  -p ascension-platform-windows --all-targets                 # exit 0
cargo clippy --locked --target x86_64-pc-windows-gnu \
  -p ascension-platform-windows --all-targets -- -D warnings # exit 0

cargo test --locked --target x86_64-pc-windows-gnu \
  -p ascension-platform-windows --lib --no-run                    # exit 0
```

The cross-built test executable was
`ascension_platform_windows-736003376af111f6.exe`, 13,766,288 bytes, with
SHA-256
`dee9f393e28b2c513dd032609fe2a0e32b0ab735de7ae15f4f25529a02541df0`.
The root independently copied and SHA-256 verified this artifact in a fresh
owned Windows temporary directory, then executed it through Windows PowerShell
with `--test-threads=1 --nocapture` and a 55-second outer deadline. Native result:
exit 0, 29 passed, zero failed, one ignored, 3.52 seconds. This includes
`newly_created_job_owner_matches_current_token_user`,
`planned_job_recovery_rejects_an_unrelated_job_limit`, and
`service_binding_rejects_a_different_existing_config`. The symlink-privilege
test remained explicitly ignored; no privilege setting was changed.

This is native component validation, not service installation or hosted-runner
validation. The integrated Windows CI/workspace gate must still pass at the
published commit before the remote failures can be marked closed.

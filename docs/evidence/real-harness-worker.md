# Real watchdog to harness worker smoke

Classification: confirmed native Linux watchdog-to-harness process-boundary
evidence for the exact run recorded below. The test remains ignored by default;
a default skip is not an execution pass. This is not live-host, gameplay,
provider, release activation, service installation, or reboot evidence.

`crates/watchdog/tests/real_harness_worker.rs` is the smallest cross-binary smoke for the native
worker boundary. It requires all of the following before it will run:

- `ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE=1`, an explicit operator gate;
- a separately built `sts2-harness-runtime` selected by
  `STS2_HARNESS_RUNTIME_BINARY` and pinned by `STS2_HARNESS_RUNTIME_SHA256`;
- a running Linux systemd user manager and cgroup-v2 controls. The helper creates
  its own unique, bounded delegated scope; it does not reuse an existing unit.

The fixture stages the supplied harness bytes, the built `CARGO_BIN_EXE_watchdog` image,
and `/usr/bin/true` as hash-verified, owner-local, non-writable images. It also owns a loopback
listener on an ephemeral port that returns bounded HTTP 503
responses; that actual selected address is included in the harness runtime fingerprint. It
writes a protected watchdog configuration, initializes the watchdog-owned SQLite store, and
starts the staged actual watchdog daemon. The daemon's native process manager sends the
real bootstrap to the staged `sts2-harness-runtime`; no fake endpoint or in-process supervisor
stands in for either binary.

After the worker is observed as `Running` with an authenticated `Running` control witness, the
test submits one empty `runtime_v3_episode` job through a separate watchdog `Store` connection.
It waits for the durable handoff to reach `Admitted`, or a validated terminal outcome if the
downstream fault fixture settles quickly. `Admitted` is the watchdog record written only after
the worker's authenticated dispatch response is `Accepted`; a quarantined job is also accepted
when the store validates the retained admitted handoff and its job/attempt projection. It then
writes durable `Stopped` intent through another store connection and requires successful daemon
exit, missing worker endpoint, missing worker PID, a stopped component record, and the retained
handoff evidence.

The owned gateway returns HTTP 503 and the MCP image is `/usr/bin/true`; they are deliberately
downstream fault fixtures. Consequently harness execution may remain unknown or be durably
quarantined. That outcome does not manufacture settlement and does not weaken the assertion that
watchdog-to-worker admission crossed the real authenticated process boundary.

Run only from the isolated worktrees after building the exact harness image:

```text
cargo build --locked --release -p sts2-harness --bin sts2-harness-runtime

export STS2_HARNESS_RUNTIME_BINARY="$PWD/target/release/sts2-harness-runtime"
export STS2_HARNESS_RUNTIME_SHA256="$(sha256sum "$STS2_HARNESS_RUNTIME_BINARY" | cut -d ' ' -f 1)"
export ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE=1

cargo test --locked -p ascension-watchdog --test real_harness_worker -- \
  --ignored --exact real_watchdog_native_launch_reaches_built_harness_worker
```

The normal test and workspace gates continue to skip this test because it is marked `ignore`.
Compilation proves only that the test is buildable; an explicit opt-in execution of the ignored
test is required to produce native composition evidence. A skipped/default test is not a pass.
Any executed evidence must be recorded with the exact watchdog and harness revisions, binary
digests, cgroup environment, and resulting durable state.

## Initial native execution, 2026-09-09

Root invoked the ignored test inside a temporary delegated user scope using
`systemd-run --user --scope --collect --property=Delegate=yes`. No service was
installed and no game or model provider was launched. The separately built
harness image had SHA-256
`993553490a3a6b6a1fa1a0ee4372ab348dd59e84261b9b329da7c7ed21f75a53`.
It was built from the uncommitted harness integration candidate, so it is an
exploratory artifact, not a final release-set artifact.

The first attempts exposed three fixture defects: the streaming helper hashed
an already finalized digest a second time; restart-disabled policy prevented
even the initial component launch; and the debug watchdog image was not
immutable. These were corrected with a known `abc` SHA-256 regression, a single
launch/restart budget, and immutable staging of the exact watchdog bytes.

The subsequent real launch exposed a production null-identity decoding bug in
the watchdog store. A component without a process identity must return `None`,
not a SQLite column-type error. The repair retains malformed-identity errors and
has a focused missing-row/null-row/reopen/corrupt-row regression.

The native composition still failed before authenticated worker admission. The
helper executed the harness from the approved sealed memfd image; the harness
then reported `Linux worker transport I/O failed`. Source inspection identified
the fixed verifier attempting to reopen `current_exe()` as a filesystem name,
which is not valid for that sealed image. This remains failed native composition
evidence until the harness self-reexecution repair and a fresh exact-byte run
pass. A temporary diagnostic build inherited synthetic child stderr to expose
that error; the diagnostic production-source change was reverted and is not
part of the candidate.

Failed native runs retain their owner-private temporary directory, including
the durable stop and process-identity records, instead of deleting evidence
while cleanup may be uncertain. Successful runs remove that directory only
after the exact daemon/worker cleanup assertions and retained-handoff checks.

## Subsequent execution and current hold, 2026-09-09

The harness self-reexecution correction subsequently allowed the real worker to
reach authenticated `Running` control. This supersedes the earlier startup
failure, but is not a complete smoke pass. A later run failed while refreshing
an unchanged worker binding with an older audit timestamp. Watchdog commit
`280906818eacca46b48998ffbe452194b851cba5` includes the identity-preserving binding
refresh correction and its focused clock-regression tests.

After that correction, a real run again reached authenticated `Running` control,
then timed out waiting for the newly queued job: the job remained queued and no
handoff was recorded. Inspection identified the component-health path supplying
no heartbeat age even after a successful authenticated worker probe. Policy
therefore marked the component `Suspect`, and the existing requirement for a
durable `Running` component correctly prevented a claim. A same-reconciliation
authenticated heartbeat candidate is under independent review. Process liveness
alone must not become a heartbeat, and the repair must preserve readiness,
quarantine, and operator-stop gates.

The failed fixture retained its private databases and images. Durable desired
mode and component state were `Stopped`, with the worker process identity
cleared. Retained evidence was not deleted. No provider or game was launched.

Further native execution is held pending review of the test's cleanup authority.
The proposed manager-owned scope has a 120-second maximum runtime and a
five-second stop timeout, but its helper-command bounds, pre-admission failure
paths, and identity-safe cleanup still require correction. A compiling or
pure-test-passing scope helper is not proof that these native paths work.

The current harness candidate is commit
`baabf9767264de11e09cd65cc7262ba36664ec2d`. An incremental locked release build at
that clean source revision succeeded and produced SHA-256
`77d90b453f5d075bd035e5773e1182014fc303797da65eef1208d159df4ebcf2`.
That artifact has not yet passed the complete watchdog-to-worker smoke. The
build is not a clean-room cross-repository release build, and neither passing
CI nor authenticated startup establishes successful job handoff or recovery.

## Confirmed native handoff, 2026-09-09

After independent source review of the same-pass heartbeat and cleanup helper,
root ran the explicitly gated test from the integrated candidate. Result:
**1 passed, 0 failed, 0 ignored**, in **114.50 seconds** total test time. This
duration includes fixture staging and cleanup; it is not a measured gameplay
recovery latency or soak duration.

The actual watchdog image was SHA-256
`7dc810a347e32653b961cf0fe6ebea0348e523c131b7b9d0d8303d54c4ccc2c3`.
The separately built harness was the `baabf9767264de11e09cd65cc7262ba36664ec2d`
artifact above, SHA-256
`77d90b453f5d075bd035e5773e1182014fc303797da65eef1208d159df4ebcf2`.
Watchdog source at execution was `d50c475ebb2d9ec576da46255e9b3d3e41a47fbe`
plus the local staged-release module and native smoke/helper integration recorded
with this evidence. This was an incremental debug build, not a clean release-set
rebuild.

The prebuilt test executable was invoked with the exact gate, independently
pinned harness path/digest and arguments:

```text
real_harness_worker-8b33f11f9ab192bd --ignored --exact \
  real_watchdog_native_launch_reaches_built_harness_worker --nocapture
```

The assertions verified authenticated `Running` control, a real cross-process
dispatch admission, valid retained handoff/job/attempt projection, durable
`Stopped` intent, successful daemon exit, absent worker endpoint/process and
cleared component process identity. The scope helper additionally verified the
original cgroup's emptiness. Successful cleanup allowed only this run's private
fixture directory to be removed; earlier failed fixtures remain retained.
Post-run read-only checks found no watchdog process or matching temporary user
scope. No service was installed and no game, model provider, host reboot or
release activation occurred. The downstream HTTP 503 and MCP `/usr/bin/true`
fixtures remain deliberately synthetic and cannot prove episode completion.

## Current exact endpoint image run, 2026-09-10

The endpoint producer is now the clean harness PR #66 source
`ef8c45e853d5f86c2653159a449826ffc20b5950`, rebased onto current harness main
`63dc563690c93c575e75228f54672c1689d8a879`. Root rebuilt the locked release
image at `/home/timot/sts2-harness-runtime-endpoint-image-wave48`; its mode is
owner-executable and non-writable (`0500`) and its SHA-256 is
`4b71eeb3c9ff410707ff2272e730889b1378cf4cae1a6b08c7531233f3bb48f2`.

With watchdog PR #9 source `f5eaf5e35be025015a28da931aa973a0ade8f0ef`, root ran:

```text
ASCENSION_WATCHDOG_REAL_HARNESS_SMOKE=1 \
STS2_HARNESS_RUNTIME_BINARY=/home/timot/sts2-harness-runtime-endpoint-image-wave48 \
STS2_HARNESS_RUNTIME_SHA256=4b71eeb3c9ff410707ff2272e730889b1378cf4cae1a6b08c7531233f3bb48f2 \
CARGO_TARGET_DIR=/dev/shm/watchdog-integrated-smoke-target \
cargo test --offline --locked -p ascension-watchdog --test real_harness_worker -- \
  --ignored --exact real_watchdog_native_launch_reaches_built_harness_worker --nocapture
```

Result: **1 passed, 0 failed, 0 ignored**, **23.21 seconds**. The test crossed
the actual watchdog process manager, Linux bootstrap frame, authenticated peer
proof, worker control probe, one durable dispatch admission, stop intent, and
owned descendant cleanup. It does not establish a native Windows endpoint,
systemd/SCM service installation, game or provider execution, host settlement,
reboot recovery, release activation, or soak. The HTTP 503 gateway and
`/usr/bin/true` MCP remain downstream synthetic faults by design.

## Post-merge endpoint hardening rerun, 2026-09-10

Harness PR #66 hardening feature head
`58dede2eb661133d8910a1f785e8a90346efe8dd` auto-merged to current harness main
`a0ace6712686cb30d6f0b556cb6814ad4c0721d1` after hosted quality/policy runs
`34542578041` and `34542578085` passed. The hardened image was rebuilt at
`/home/timot/sts2-harness-runtime-endpoint-image-hardening`, retained with mode
`0500`, and verified at SHA-256
`5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f`.

The exact native smoke command was rerun with that image and the same watchdog
PR #9 source. Result: **1 passed, 0 failed, 0 ignored**, **25.33 seconds**.
In addition to the earlier bootstrap/control/admission/stop assertions, this
run exercises the endpoint source containing true-EOF bootstrap parsing,
bounded authentication slots/deadlines, and sealed runtime-image snapshots.
The gateway remained an HTTP-503 fixture and MCP remained `/usr/bin/true`; no
gameplay, provider settlement, installed service, release activation, reboot,
or soak claim follows.

## Train native VM validation, 2026-09-11

Watchdog PR #9 candidate `cfd06860a77e8be11267eaeb668452ac810a8a22` was
exercised on the supplied Train guests with fresh
guest-side copies of the test binaries.  These runs are native process-boundary
evidence only; they do not install a service, launch the game, invoke a model
provider, reboot a host, or establish live recovery.

On `sts.home.complete.tech-slay-the-spire`, the explicitly gated ignored test
`real_watchdog_native_launch_reaches_built_harness_worker` completed with
**1 passed, 0 failed, 0 ignored** in **9.44 seconds**.  The guest used the
watchdog image SHA-256
`96d0eca7d22f585fbacb9c6162e09f4bb698c458170501e23308a65f1cb2a4f6`, the
harness endpoint image SHA-256
`5286706d03c27c00e32493c1adf8864e972f7a53d1f863c046aed32d56a1644f`, and the
fresh test executable SHA-256
`2220833acae0c7d3f88ec9d7dd2dff1637fb0070646274b94b9c5f67d575009d`.  The
run verified authenticated worker admission, durable stop intent, daemon and
worker teardown, and exact original-cgroup cleanup.  The endpoint printed a
bounded `runtime-v3 execution store is busy` diagnostic during the intentional
stop race; the assertions still passed.  The gateway and MCP inputs remained
the documented HTTP-503 and `/usr/bin/true` fault fixtures, so this is not an
episode-settlement or gameplay result.  Earlier failed fixture directories were
retained for inspection.

On `sts.home.complete.tech-windows`, fresh native guest execution passed the
cross-built suites: synthetic process recovery **7/7**, worker bootstrap **4/4**,
gateway health/bootstrap **4/4**, and current-process identity **2/2**.  The
Windows safety regression suite passed **5** default tests with **2** expected
ignored tests; the explicitly invoked interactive owner-death case then passed
**1/1**.  The adjacent synthetic fixture used by that case was the exact
cross-built `platform_synthetic.exe` image, SHA-256
`958438bc1f9303ce006a640876cf8d1b3505adf8d97c8305e6794ac9bd777e10`.
Cross-target locked Clippy also passed.  These results cover native Windows
process and identity/cleanup behavior, not SCM installation, session-0 service
operation, reboot recovery, game execution, or provider settlement.

The Linux cgroup boundary test requiring a separately provisioned protected
bootstrap remains explicitly gated; a prior stale protected-bootstrap attempt
failed before exercising the requested boundary and is not reported as a pass.

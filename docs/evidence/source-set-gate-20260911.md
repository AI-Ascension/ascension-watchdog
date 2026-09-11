# Cross-repository source-set gate — 2026-09-11

Classification: `source-set verifier implemented; candidate rejected`. The
gate is read-only evidence about already fetched worktrees. It is not a build,
release activation, service, live-host, reboot, or soak result.

The executable form is:

```text
watchdog release source-set verify --manifest PATH \
  --repo NAME=PATH [...] [--artifact NAME=PATH [...]]
```

It requires the seven core source repositories in the candidate manifest,
checks every supplied worktree for a full pinned commit, a clean status, and
the expected GitHub origin, then checks the protocol artifact `SHA256SUMS`
files, required contract files, current consumer commit bindings, and selected
wire/golden bytes. Failed admission prints the complete JSON report to stdout
and exits 1. It never fetches, builds, installs, activates, or runs a
companion.

The gate was run against the candidate manifest and the eight current local
source worktrees after commit `b4cda14ea578e9ad33f8142698d494aeb9f3a61f`.
The watchdog binary built successfully and the verifier returned exit 1 with
`admitted=false`. Seven companion source reports were clean and exactly
pinned; the candidate's watchdog pin still described the earlier source
revision at capture time, so that mismatch was retained as a failure.

All four inspected `coop-native-v1` artifacts passed their checksum-file
integrity checks: 34 entries for the protocol copy and 25 entries for each
consumer copy. Schema, conformance, and golden contract bytes matched across
the copies. Admission correctly remained closed because the manifest and
consumer-conformance bytes differed, and gateway/MCP copies contained pending
or non-current consumer bindings. No artifact bytes were normalized to make
the gate pass.

The verifier's own unit and CLI regressions pass, as does the full serial
workspace gate. A future release candidate must regenerate the source
manifest, produce one current consumer-conformance set, and rerun this gate
before any release or host claim is considered.

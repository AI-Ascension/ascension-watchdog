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

The first two gate runs are preserved in the source history. The current
read-only run uses watchdog commit `538346e8909a2f4fc23e5b3ea9ec2960b8b34530`,
merged gateway main commit `f4d14091ce1f3b5327925a7a536e2c7bf7b0c56b`, and
manifest digest
`0902e33c084b97efc5ee0afd4af120c4b61fe527bbbc5bf13a580d2a8ccbae0d`; it
returned exit 1 with `admitted=false` (report
`/home/agent/wd-tmp-0911/source-set-report-1041.json`). All eight supplied
source worktrees were clean and exactly pinned for this run. The remaining failures are the
consumer artifact boundary: gateway/MCP copies retain pending conformance,
consumer bindings are not the selected current revisions, and the contract
manifests/consumer-conformance files are not byte-identical across copies.
The root source pin was supplied from a clean detached worktree at `538346e`,
because the candidate manifest is committed in the newer documentation head;
the verifier therefore checks the selected implementation revision rather than
mistaking the evidence update itself for the release source.

All four inspected `coop-native-v1` artifacts passed their checksum-file
integrity checks: 34 entries for the protocol copy and 25 entries for each
consumer copy. Schema, conformance, and golden contract bytes matched across
the copies. Admission correctly remained closed because the manifest and
consumer-conformance bytes differed, and gateway/MCP copies contained pending
or non-current consumer bindings. No artifact bytes were normalized to make
the gate pass.

The verifier's own unit and CLI regressions pass. The selected 538 source-set
worktree has the earlier full serial workspace evidence (210 watchdog library
tests passed, with four expected ignored tests); the current PR head
`f5b81f4` was separately rerun with the same full serial workspace command and
exited zero, with focused systemd notifier 5/5 and service-loop 6/6 passing. A
future release candidate must regenerate the source
manifest, produce one current consumer-conformance set, and rerun this gate
before any release or host claim is considered.

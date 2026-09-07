# Managed G6 and catalog probe rerun

Classification: confirmed managed synthetic probe, not cross-repository or
live-game recovery.

After G6 author reported stable source, root ran the full source-only probe:
`dotnet run --project experiments/managed-rust-interop/gameplay-tests/RuntimeV3ValidationProbe.csproj --configuration Release`.

Two test-data corrections were necessary: catalog identity strings must obey
the frozen ASCII identity grammar (delimiter/escaping characters are tested as
rejected inputs), and the lifecycle test's old hardcoded delimiter-catalog hash
was replaced by its current host catalog digest. The independent catalog checks
still compare the helper digest against raw actual state/legal-action response
bytes and verify ordering and invalid-generation rejection.

Final rerun: exit 0, output `Runtime-v3 managed request, receipt, and settlement
checks passed.` Companion source is still uncommitted. Prior failed attempts
remain recorded; this supersedes only their managed probe outcome.

V23 review still requires versioned gateway-issued lease installation, gateway
raw catalog capture, retained state/authority-bound catalog artifacts, and
cross-consumer validation. The successful probe does not resolve those seams.

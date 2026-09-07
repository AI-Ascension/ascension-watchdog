# Managed catalog-byte repair candidate

Classification: source-derived candidate, validation incomplete.

The managed host candidate replaces delimiter-joined action hashing with SHA-256
of the `legal_actions` JsonElement serialized using the response encoder.
`CatalogDigestChecks` compares this digest against raw catalog bytes extracted
from actual managed state and legal-action responses, including JSON escaping,
null targets, catalog ordering, and rejection of invalid generations.

Candidate identities (SHA-256):

- `RuntimeV3GameplaySupport.cs`:
  `fc132adba7b3e9536cecc4581fa1c70578c7fcf5448f763cc96a99652b15cea1`
- `CatalogDigestChecks.cs`:
  `6dd0a28b99a0fdd121181610d5701eb5a1036d0eed12db8a5cbb23fe04ae9579`

Root attempted the source-only gameplay probe with .NET:
`dotnet run --project experiments/managed-rust-interop/gameplay-tests/RuntimeV3ValidationProbe.csproj --configuration Release`.
It exited 1 while the concurrent, non-overlapping host-fence repair was still
being edited: `TryAcceptControlFence` lacked the seven-argument overload called
by `RuntimeV3GameplayRecoveryStore.Control.cs`, with an accompanying CA1822.
A CA1859 in the new catalog test was corrected afterward. No successful rerun
is claimed. The host repair owner must rerun the combined probe when stable.

Gateway catalog capture and the normative byte-contract update remain pending.
This candidate does not establish cross-consumer conformance or live-host
behavior, and its source remains uncommitted in the companion worktree.

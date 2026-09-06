# Capability evidence

Confirmed: installed CLI reports `codex-cli 0.153.4`. Bundled and cached model
catalogs list `gpt-5.6-luna` and reasoning effort `max`. The native spawn tool
accepts explicit `model`, `reasoning_effort` and `fork_turns` fields. A full-history
fork cannot override model/effort, so descendants receive explicit bounded packets
with `fork_turns: none`.

Confirmed: native thread metadata for the architecture lead records Luna/max,
actual depth 1 and parent identity. Its first turn execution context independently
records `model: gpt-5.6-luna`, `effort: max`. A child self-description is not used
as model verification. Deeper routing and enforced leaf restrictions remain
unverified pending the nested tasks and policy inspection.

The existing global configuration has a 50-thread ceiling and `max_depth = 3`.
This does not establish what the current runtime enforces. Root allocates a
stricter aggregate 12-descendant budget; reservations include managers. No global
configuration or approval/sandbox policy was changed.

The installed CLI rejects `--strict-config` for `debug` and
`app-server generate-json-schema`. Schema generation itself succeeded. Candidate
project settings are not represented as validated merely because schema generation
accepted a command. The daemon version probe found no control socket; this does
not mean the native active agents stopped.

The original objective is preserved with a final newline added; no semantic text
was changed. Original SHA-256:
`ab09c59be36fe978ffb1122d9052fa3027bb4be60888e899f3484917bb3921f3`.

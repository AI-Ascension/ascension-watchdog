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

Confirmed subsequently: a bounded non-inference `codex --strict-config ...
app-server --stdio` initialization and `config/read` returned enabled agents,
thread limit 12, inherited max depth 3, default model `gpt-5.6-luna` and default
effort `max`. The project default keys are supported. This diagnostic did not
launch a model thread or change the current session's configuration.

Capability failure: the architecture lead's actual available child tool surface
does not expose the collaboration namespace. Its attempt to access spawning
through the in-process tools object returned `TypeError: ...spawn_agent is not a
function`. Only root-native depth-1 delegation is currently demonstrated. No
alternate clients/providers or ancestry resets are permitted. Three descendant
levels and depth-4 rejection are unmet, and full assignment completion cannot be
claimed even if independent implementation succeeds.

Revalidated during the 2026-09-07 proof-conformance review: the active depth-1
reviewer's callable tool schema again exposed no child-spawn/collaboration
function. It therefore created no depth-2 coordinator or depth-3 specialist and
made no depth-4 attempt. Root released the two reserved descendant slots. This
is a recorded capability failure, not a successful nested-routing smoke test;
independent implementation and verification continued without an alternate client.

The project configuration and explicit lead/coordinator/leaf role files were
parsed by the installed client. A fresh `config/read` with layers reports the
project layer disabled because this newly created repository is not individually
trusted. The effective diagnostic configuration therefore remains the global
50-thread default. No trust, hook, permission or approval setting was changed to
force loading. Native root spawn arguments still independently establish Luna/max;
the root registry bounds actual descendants. Custom role selection is not exposed
by the current root spawn schema, so the leaf's `agents.enabled = false` setting
is prepared configuration, not observed leaf-tool enforcement.

The original objective is preserved with a final newline added; no semantic text
was changed. Original SHA-256:
`ab09c59be36fe978ffb1122d9052fa3027bb4be60888e899f3484917bb3921f3`.

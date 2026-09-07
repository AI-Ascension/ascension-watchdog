# `runtime-v3-gameplay` release-like artifact

This artifact defines the neutral fair-play semantic boundary between the host bridge and its
gateway, MCP, and harness consumers. It carries ordinary player-visible observations, a complete
host-generated typed `LegalAction` set, generation/lease identity, explicit accepted/settled/
rejected/unknown/cancelled outcomes, and bounded wait/recovery messages.

The normative source is [`schemas/runtime-v3-gameplay.schema.json`](../../schemas/runtime-v3-gameplay.schema.json);
`schema.json` is its byte-identical package copy. The schema contains no host objects, raw input,
process commands, saves, credentials, future RNG, or unrevealed outcomes. A visible seed is text
only and is never an authorization or prediction input.

The artifact is contract evidence only. Consumer mapping, host-thread behavior, gateway lifecycle,
MCP transport, Exo execution, and live game-effect settlement remain `unverified` until their
separate gates run.

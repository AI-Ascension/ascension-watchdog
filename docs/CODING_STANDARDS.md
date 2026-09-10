# Planning-stage standards profile

The default bootstrap commit contains architecture and orchestration documents,
JSON records and an implementation prompt. It has no accepted Cargo workspace,
product executable, service wrapper or test target. The active standards scope
is documentation and configuration; Rust, native-service, live-host, reboot and
soak lanes are not applicable to this source revision. An open implementation
branch is not default-branch adoption.

AGENTS.md and architecture.md retain ownership authority. Preserve the recorded
workspace-manifest.json source pins as historical baseline inputs, not a current
release set. The shared profile/lock pins AI-Ascension/.github standards data.
UTF-8/LF is the source default. Keep exact schema identifiers and owner names.

Parse each JSON document, validate local links and check Git whitespace using the
local standards command in standards-profile.toml. Missing targets must fail a
claimed executable lane; do not initialize a Cargo workspace or install a service
to make an inapplicable lane green. Future accepted product code must update the
profile and add actual pinned build, lint, tests and fault-injection coverage in
the same reviewed change. No new runtime authority is granted by these standards.

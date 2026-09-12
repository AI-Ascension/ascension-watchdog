# Windows native qualification

Ordinary PR CI is **synthetic evidence only**, including its hosted Windows
matrix. A successful build, cross-compilation, synthetic child test, or a
non-session-0 Windows runner never qualifies a native release.

`native-qualification.yml` is manual and requires an approved self-hosted
Windows runner labelled `session-0`. It neither installs a service nor activates
or publishes a release. It records the repository, exact Git SHA, evidence
class (`synthetic` or `native-session0`), session, required check IDs, outcomes,
and SHA-256 of the captured test receipt. The verifier recomputes the supplied
receipt digest, and the workflow retains both receipt and evidence as an artifact.
`watchdog qualification verify-native` rejects unavailable, malformed,
synthetic, wrong-repository, wrong-SHA, non-Windows, non-session-0, incomplete,
or failed evidence with a nonzero exit.

The local Rust verifier tests a valid fixture and deliberate synthetic,
wrong-session, and wrong-revision failures. Those fixture tests validate the
gate only; Linux has no Windows session-0 execution evidence.

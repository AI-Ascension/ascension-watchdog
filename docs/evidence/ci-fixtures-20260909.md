# Hosted CI fixture portability

The hosted Linux runner used UID 1001, colliding with the broker test's fixed
synthetic target identity. The fake backend now uses a nonzero UID/GID distinct
from the invoking peer, including when the test itself runs as 65534. No real
account lookup, privilege transition, or account change is performed.

Windows Clippy also rejected unnecessary raw-string hashes in the test-owned
credential DACL setup. The PowerShell payload is otherwise unchanged.

Two hosted runtime uncertainty tests failed because their initial synthetic
launch did not settle. They did not reproduce in the focused tests or full
serial library suite. The assertion now includes the bounded fixture report,
mode, component state, and unsettled intents. No speculative production fix,
deadline increase, or weakened assertion was applied; their hosted result must
be checked again and diagnosed from that evidence if still failing.

The author ran the focused runtime tests (3 passed), the serial all-feature
watchdog library suite (92 passed, 2 host tests ignored), formatting, and strict
test Clippy before handoff. Root review added the explicit 65534 collision
fallback. These local checks are not a claim that hosted CI has passed.

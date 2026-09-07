# Ascension Watchdog

Deterministic Rust deployment supervision and crash recovery for AI-Ascension.

This is a bounded [Ascension](https://github.com/AI-Ascension/sts2-harness)
operations component. **The Climb — by AI Ascension** does not imply that a
watchdog service, 24/7 operation, or recovery guarantee has been verified.

Status: implementation in progress; no service, live-host recovery, reboot or soak
validation is claimed. See the requirement matrix and evidence records as gates
are implemented and independently verified.

The OS service manager owns the watchdog. The watchdog supervises gateway and
harness executables. The gateway owns game lifecycle authority and uses a
restricted host broker. The harness owns MCP and provider processes. Uncertain
game operations remain subject to owner-side reconciliation, never blind retry.

MIT licensed. This project does not distribute game files or grant rights to them.

# Integrated P8 focused gates

Classification: confirmed Linux component/synthetic execution and Windows
cross-compilation; native service execution remains unverified.

Root integrated `a64b017`, `25bfdfa`, and `40a27f5` as `eac4508`, `9638d54`,
and `1e0af35`. The synthetic typed-uncertainty mapping from P7 was preserved.
The helper readiness acknowledgment now precedes GO and closing parent
bootstrap keepalives; bootstrap descriptors remain CLOEXEC.

Root executed on this integrated source:

- `cargo test --locked -p ascension-watchdog --lib --test linux_boundary --test core`:
  45 library, eight core, and three Linux-boundary tests passed. Two native
  cgroup tests were explicitly ignored.
- `cargo check --locked --workspace --all-targets --target x86_64-pc-windows-gnu`:
  exit 0.

The delayed-readiness regression exercises the acknowledgment lifetime, not a
complete native helper/cgroup launch. V25 independent integrated source review
is active. W10 original launch-context persistence is not yet integrated.
These focused gates do not establish a full release or Windows runtime pass.

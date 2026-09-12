# Rootless Podman environment and in-container composition — 2026-09-12

Classification: `host container environment setup plus a container-scoped
cross-repo composition check`. This is not gameplay, not the watchdog service,
and not the 24-hour soak.

## Environment

On the supplied Train host (`train.home.complete.tech`), the rootless Podman
environment for the `completetrain` account was verified and extended for this
work:

- `podman version 4.9.3`, rootless (`podman info` → `Rootless=true`, overlay
  graph driver); `podman.socket` active for both the user and system managers;
  `/etc/subuid` and `/etc/subgid` already contain the account.
- Created a dedicated network `ascension-watchdog` and volume
  `ascension-watchdog-state`, and verified a container can use both.

The rootful supervisor soak (`ascension-soak`) continues independently; it is a
privileged container because the shipped unit uses `Delegate=yes`.

## In-container composition check

The native cross-repo composition test
(`runtime_v4_executable_composition`, operator test from `sts2-harness`) was run
inside a **rootless** Podman container on the same host, with the built gateway,
MCP, harness, and composition-test binaries mounted read-only:

```text
podman run --rm -v /home/completetrain/wd-composition-20260912:/work:ro \
  docker.io/library/ubuntu:24.04 bash -c \
  'cd /work && STS2_GATEWAY_BINARY=/work/sts2-gateway-runtime \
   STS2_MCP_BINARY=/work/sts2-mcp-server \
   STS2_HARNESS_RUNTIME_BINARY=/work/sts2-harness-runtime TMPDIR=/tmp \
   ./runtime_v4_executable_composition-... --ignored --exact \
   executable_runtime_v4_composes_unknown_reconcile_and_foreign_state_fence'
```

Result: `1 passed` — the same unknown-outcome reconciliation without a second
effect and foreign-state fencing verified on the host also holds inside a
rootless container, so the composition is reproducible without root.

## Boundary

Verified: a rootless Podman environment is available on the host and can run the
Ascension cross-repo composition artifacts. Not verified: the 24-hour
cross-repository gameplay soak (still needs the companion synthetic game
downstream as a runnable service), native Windows/WSL paths, host-level reboot,
or nested Luna-Max delegation.

# Operations and deployment configuration guidance

Shell, PowerShell, Compose, Dockerfile, systemd, and deployment configuration are operational
code. Keep declared dialects and tool versions explicit, parse data rather than executing it, and
check native exit codes. Own every subprocess lifecycle, bound waits and retries, and report
partial initialization without claiming a complete service.

## Observability

The observability repository owns its Compose topology, image wrappers, OTLP collector, stateful
volumes, and operational docs. Run the existing local checks in their order:

```bash
for script in deploy/init.sh deploy/laminar/bootstrap-project-key.sh tests/*.sh tests/fixtures/*; do bash -n "$script"; done
shellcheck --severity=warning deploy/init.sh deploy/laminar/bootstrap-project-key.sh tests/*.sh tests/fixtures/*
bash tests/bootstrap.sh
bash tests/validation-regressions.sh
bash tests/compose-invariants.sh
docker compose --env-file deploy/.env.example -f deploy/compose.yaml config --quiet
bash tests/compose-required-settings.sh
docker buildx build --check --file deploy/Dockerfile.mlflow deploy
docker buildx build --check --file deploy/Dockerfile.laminar deploy
```

The default host listeners stay loopback-only. Internal container binds, published host ports,
credentials, data volumes, health, ingestion, persistence, and restart survival are different
claims. Do not use broad cleanup, `down -v`, volume deletion, process-name kills, or shared
deployment changes as troubleshooting shortcuts.

## Planning-stage repositories

`ascension-watchdog` and `ascension-map-visualizer` remain planning/bootstrap profiles until an
accepted product manifest, owner implementation, and deterministic target checks exist. Their
prompt/configuration files are source-derived planning evidence; they do not authorize service
installation, game access, or a product workspace.


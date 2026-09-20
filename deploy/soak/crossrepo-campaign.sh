#!/bin/sh
# Reproducible cross-repo campaign runner.
#
# Keeps one synthetic downstream (the sts2-harness operator test server) running
# for the whole campaign while the gateway + MCP + harness stack runs one
# episode per iteration, and periodically injects a fault.
# Records {"ts","iteration","result"} and {"ts","fault","result"} lines. Each
# failed iteration retains a bounded runtime/gateway log pair and records their
# relative paths and runtime exit status.
#
# Two topologies:
#   * default: each iteration starts a fresh gateway (the legacy single-episode
#     contract, which the attached adapter still enforces);
#   * --single-deployment: ONE gateway process serves the whole window and every
#     episode opts in to the gateway's negotiated repeated-episode lease profile
#     (STS2_EPISODE_PROFILE=true, sts2-gateway ADR 0033 / harness #262) with a
#     fresh lease id and a strictly increasing lease epoch. Iteration records
#     carry "lease_epoch" and the first record is {"ts","mode":"single-deployment"}.
#     The profile negotiates only on the gateway's durable recovery path, so the
#     gateway/harness recovery environment must be supplied with --env-file (see
#     docs/evidence/single-deployment-soak-prerequisite-20260917.md).
#
# Fault kinds (--fault-kinds, comma separated, injected round-robin every
# --fault-interval-seconds): downstream_restart (legacy alias of restart),
# restart, archive, budget, telemetry_outage. Every injected fault records
# {"ts","fault":KIND,"result":"recovered"|"failed"[,"detail":...]}.
#
# Usage:
#   crossrepo-campaign.sh --bin-dir DIR --results PATH --duration-seconds N \
#     [--single-deployment] [--fault-kinds LIST] [--env-file FILE] \
#     [--fault-interval-seconds N] [--max-failure-diagnostics N] \
#     [--max-execution-stores N] \
#     [--mod-addr ADDR] [--gateway-port-base N] [--exo-revision SHA]
#
# --env-file also supplies the gateway's durable recovery environment. When the
# host lease key is configured the campaign drives the durable bring-up the
# repeated-episode profile requires (boot authority, then host fence) before the
# window starts, because the gateway refuses every allocate with
# recovery_host_fence_required until it holds an accepted fence. A refused
# bring-up ends the campaign before the clock starts rather than recording a
# whole window of iterations that could only fail.
set -eu

usage() {
    printf '%s\n' 'usage: crossrepo-campaign.sh --bin-dir DIR --results PATH --duration-seconds N [--single-deployment] [--fault-kinds LIST] [--env-file FILE] [--fault-interval-seconds N] [--max-failure-diagnostics N] [--max-execution-stores N] [--mod-addr ADDR] [--gateway-port-base N] [--exo-revision SHA]' >&2
    exit 64
}

bin_dir=
results=
duration=
single_deployment=0
fault_kinds=
env_file=
fault_interval=900
max_failure_diagnostics=16
max_execution_stores=64
mod_addr=127.0.0.1:20001
gateway_port_base=21000
budget_burst=3
# The reviewed Exo source revision the harness admits (sts2-harness ADR 0017,
# `EXO_SOURCE_REVISION` at the pinned harness); the bounded synthetic bridge is
# a raw-wire probe, acknowledged explicitly with STS2_EXO_ADMISSION=legacy.
exo_revision=b06869ab789dee3f80ca474b5fa89dbe47ccb859

# Durable recovery constants, pinned to the gateway's recovery contract
# (`watchdog-recovery-v1`). They are the same values
# `deploy/soak/host-sideband-gateway-probe.sh` drives by hand, kept here so the
# campaign can perform the same bring-up without an operator.
recovery_contract=watchdog-recovery-v1
recovery_schema_digest=fb934d3157485aaf6e13e6ebbb213ec8a14c7fc6f5eeebc06b7a22c1f0009217
runtime_v3_schema_digest=8e99cea36b7ede97532348fd8efe302ca79260895265a7bf14ddf7e006d8ff63
zero_digest=0000000000000000000000000000000000000000000000000000000000000000
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir) [ "$#" -ge 2 ] || usage; bin_dir=$2; shift 2 ;;
        --results) [ "$#" -ge 2 ] || usage; results=$2; shift 2 ;;
        --duration-seconds) [ "$#" -ge 2 ] || usage; duration=$2; shift 2 ;;
        --single-deployment) single_deployment=1; shift ;;
        --fault-kinds) [ "$#" -ge 2 ] || usage; fault_kinds=$2; shift 2 ;;
        --env-file) [ "$#" -ge 2 ] || usage; env_file=$2; shift 2 ;;
        --fault-interval-seconds) [ "$#" -ge 2 ] || usage; fault_interval=$2; shift 2 ;;
        --max-failure-diagnostics) [ "$#" -ge 2 ] || usage; max_failure_diagnostics=$2; shift 2 ;;
        --max-execution-stores) [ "$#" -ge 2 ] || usage; max_execution_stores=$2; shift 2 ;;
        --mod-addr) [ "$#" -ge 2 ] || usage; mod_addr=$2; shift 2 ;;
        --gateway-port-base) [ "$#" -ge 2 ] || usage; gateway_port_base=$2; shift 2 ;;
        --exo-revision) [ "$#" -ge 2 ] || usage; exo_revision=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$bin_dir" ] && [ -n "$results" ] && [ -n "$duration" ] || usage
case "$max_failure_diagnostics" in
    ''|*[!0-9]*) usage ;;
esac
[ "$max_failure_diagnostics" -gt 0 ] || usage
case "$max_execution_stores" in
    ''|*[!0-9]*) usage ;;
esac
[ "$max_execution_stores" -gt 0 ] || usage

# The fault matrix is closed: an unknown kind is a usage error, never silently
# skipped, so a misspelled matrix cannot produce a campaign with no faults.
if [ -z "$fault_kinds" ]; then
    if [ "$single_deployment" -eq 1 ]; then
        fault_kinds=restart,archive,budget,telemetry_outage
    else
        fault_kinds=downstream_restart
    fi
fi
fault_list=$(printf '%s' "$fault_kinds" | tr ',' ' ')
for kind in $fault_list; do
    case "$kind" in
        downstream_restart|restart|archive|budget|telemetry_outage) : ;;
        *) printf '%s\n' "unknown fault kind: $kind" >&2; exit 64 ;;
    esac
done
[ -n "$fault_list" ] || usage

# Optional KEY=VALUE environment for the gateway and harness launches (for
# example the durable recovery environment the repeated-episode profile needs).
# Only STS2_* names are accepted; values set explicitly below take precedence.
if [ -n "$env_file" ]; then
    [ -f "$env_file" ] || { printf '%s\n' "env file is missing: $env_file" >&2; exit 66; }
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*) continue ;;
        esac
        name=${line%%=*}
        value=${line#*=}
        case "$name" in
            STS2_*) ;;
            *) printf '%s\n' "env file line is not an STS2_ assignment: $line" >&2; exit 64 ;;
        esac
        case "$name" in
            *[!A-Z0-9_]*) printf '%s\n' "env file name is invalid: $name" >&2; exit 64 ;;
        esac
        export "$name=$value"
    done < "$env_file"
fi

for name in synthetic_mod_server sts2-gateway-runtime sts2-harness-runtime sts2-mcp-server bridge.sh; do
    [ -e "$bin_dir/$name" ] || { printf '%s\n' "missing campaign input: $bin_dir/$name" >&2; exit 66; }
done
mkdir -p "$results"
results_file=$results/iterations.jsonl
diagnostics_dir=$results/failure-diagnostics
archive_dir=$results/archive
mod_log=$results/synthetic-mod.log
mkdir -p "$diagnostics_dir" "$archive_dir"
: > "$results_file"

now_iso() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# One recovery frame per call, with fresh message and correlation identities.
# The gateway authenticates the call with the control-scope bearer token plus
# the capability header, so the frame proof stays null exactly as the shipped
# operator probe sends it.
recovery_frame() {
    kind=$1 capability=$2 payload=$3
    jq -cn \
        --arg contract "$recovery_contract" \
        --arg schema "$recovery_schema_digest" \
        --arg message "$(cat /proc/sys/kernel/random/uuid)" \
        --arg correlation "$(cat /proc/sys/kernel/random/uuid)" \
        --arg sent_at "$(date -u +%Y-%m-%dT%H:%M:%S.000Z)" \
        --arg principal "${STS2_CALLER_ID:-harness}" \
        --arg capability "$capability" \
        --arg kind "$kind" \
        --argjson payload "$payload" \
        '{contract:$contract, schema_digest:$schema, message_id:$message,
          correlation_id:$correlation, sent_at:$sent_at,
          actor:{principal_id:$principal, role:"harness"},
          auth:{principal_id:$principal, capability:$capability, proof:null},
          kind:$kind, payload:$payload}'
}

# The served gateway enforces a closed header allowlist, so the request must not
# carry curl's default User-Agent or Accept headers.
recovery_post() {
    path=$1 capability=$2 frame=$3
    status=$(curl -sS -o "$bringup_body" -w '%{http_code}' \
        -H "Authorization: Bearer $recovery_token" \
        -H 'Content-Type: application/json' \
        -H "x-sts2-recovery-capability: $capability" \
        -H 'User-Agent:' -H 'Accept:' \
        --data-binary "$frame" \
        "http://$gateway_addr$path" 2>/dev/null) || status=000
    printf '%s' "$status"
}

# The repeated-episode lease profile is gateway-process-local state reachable
# only through the durable recovery path (sts2-gateway ADR 0033): until the
# deployment holds a boot authority *and* an accepted host fence, every
# `POST /v1/sessions/allocate` answers `503 recovery_host_fence_required`, so a
# window that skips this bring-up can only ever record failed iterations.
#
# Fail closed at every step. A refused bootstrap, a refused fence, a fence that
# is not bound to the served boot, or a missing prerequisite ends the campaign
# before the clock starts; the window is never opened against a gateway that
# cannot allocate.
bringup_durable_recovery() {
    command -v jq >/dev/null 2>&1 || {
        printf '%s\n' 'the configured durable recovery environment needs jq to build its frames' >&2
        exit 66
    }
    command -v curl >/dev/null 2>&1 || {
        printf '%s\n' 'the configured durable recovery environment needs curl to drive the bring-up' >&2
        exit 66
    }
    recovery_token=${STS2_RECOVERY_TOKEN:-}
    deployment_id=${STS2_DEPLOYMENT_ID:-}
    instance_id=${STS2_INSTANCE_ID:-}
    missing=
    [ -n "$recovery_token" ] || missing="$missing STS2_RECOVERY_TOKEN"
    [ -n "$deployment_id" ] || missing="$missing STS2_DEPLOYMENT_ID"
    [ -n "$instance_id" ] || missing="$missing STS2_INSTANCE_ID"
    [ -n "${STS2_RECOVERY_STORE:-}" ] || missing="$missing STS2_RECOVERY_STORE"
    if [ -n "$missing" ]; then
        printf '%s\n' "STS2_RUNTIME_HOST_LEASE_KEY is set, so the durable recovery environment must also supply:$missing" >&2
        exit 66
    fi
    bringup_dir=$results/.bringup
    mkdir -p "$bringup_dir"
    bringup_body=$bringup_dir/body.json
    incarnation=$(cat /proc/sys/kernel/random/uuid)

    boot_payload=$(jq -cn \
        --arg deployment "$deployment_id" --arg instance "$instance_id" --arg incarnation "$incarnation" \
        --arg zero "$zero_digest" --arg schema "$runtime_v3_schema_digest" \
        '{deployment_id:$deployment, instance_id:$instance, instance_incarnation:$incarnation,
          release:{release_digest:$zero, config_digest:$zero,
                   profile_digest:$zero, runtime_v3_schema_digest:$schema},
          lease_policy:{ttl_seconds:30, renewal_interval_seconds:10}}')
    status=$(recovery_post /v1/recovery/bootstrap bootstrap "$(recovery_frame bootstrap_request bootstrap "$boot_payload")")
    boot_status=$(jq -r '.payload.result.status // .error_code // "?"' "$bringup_body" 2>/dev/null) || boot_status=?
    boot=$(jq -c '.payload.boot // empty' "$bringup_body" 2>/dev/null) || boot=
    if [ "$status" != 200 ] || [ "$boot_status" != BOOT_AUTHORITY_CREATED ] || [ -z "$boot" ]; then
        printf '%s\n' "the durable bootstrap was refused: status=$status result=$boot_status" >&2
        tail -n 20 "$gateway_log" >&2
        exit 69
    fi

    status=$(recovery_post /v1/recovery/host-fence host_fence "$(recovery_frame host_fence_request host_fence "$(jq -cn --argjson boot "$boot" '{boot:$boot}')")")
    fence_status=$(jq -r '.payload.result.status // .error_code // "?"' "$bringup_body" 2>/dev/null) || fence_status=?
    fence=$(jq -c '.payload.fence // empty' "$bringup_body" 2>/dev/null) || fence=
    if [ "$status" != 200 ] || [ "$fence_status" != FENCE_ACCEPTED ] || [ -z "$fence" ]; then
        printf '%s\n' "the host fence was refused: status=$status result=$fence_status" >&2
        tail -n 20 "$gateway_log" >&2
        exit 69
    fi

    # The acknowledgment must be bound to the boot the served gateway presented;
    # a fence for a different identity would authorize a different deployment.
    mismatch=$(jq -rn --argjson fence "$fence" --argjson boot "$boot" \
        '["deployment_id","instance_id","instance_incarnation","boot_id","authority_generation"]
         | map(select(($fence[.]|tostring) != ($boot[.]|tostring)))
         | join(",")')
    if [ -n "$mismatch" ]; then
        printf '%s\n' "the host fence is not bound to the served boot: $mismatch" >&2
        exit 69
    fi

    boot_id=$(printf '%s' "$boot" | jq -r '.boot_id')
    authority_generation=$(printf '%s' "$boot" | jq -r '.authority_generation')
    fence_generation=$(printf '%s' "$fence" | jq -r '.fence_generation')
    printf '{"ts":"%s","bringup":"durable-recovery","bootstrap":"%s","fence":"%s","boot_id":"%s","instance_incarnation":"%s","authority_generation":%s,"fence_generation":%s}\n' \
        "$(now_iso)" "$boot_status" "$fence_status" "$boot_id" "$incarnation" \
        "$authority_generation" "$fence_generation" >> "$results_file"
}

trim_failure_diagnostics() {
    retained=$(find "$diagnostics_dir" -maxdepth 1 -type f -name 'failure-*.runtime.log' | wc -l)
    while [ "$retained" -gt "$max_failure_diagnostics" ]; do
        oldest=$(find "$diagnostics_dir" -maxdepth 1 -type f -name 'failure-*.runtime.log' | sort | head -n 1)
        [ -n "$oldest" ] || return 0
        base=${oldest%.runtime.log}
        rm -f "$oldest" "$base.gateway.log" "$base.execution.sqlite3" \
            "$base.execution.sqlite3-shm" "$base.execution.sqlite3-wal"
        retained=$((retained - 1))
    done
}

trim_execution_stores() {
    retained=$(find "$results" -maxdepth 1 -type f -name 'execution-*.sqlite3' | wc -l)
    while [ "$retained" -gt "$max_execution_stores" ]; do
        oldest=$(find "$results" -maxdepth 1 -type f -name 'execution-*.sqlite3' | sort | head -n 1)
        [ -n "$oldest" ] || return 0
        rm -f "$oldest" "$oldest-shm" "$oldest-wal"
        retained=$((retained - 1))
    done
}

# The downstream's host sideband is composed from the same environment
# `--env-file` supplies to the gateway's durable recovery path: with
# `STS2_SYNTHETIC_HOST_LEASE_KEY` set the downstream answers signed
# host-lease-control frames and reports `host_lease=enabled`, and without it it
# reports `host_lease=closed`. Both names are forwarded explicitly so this
# launch, rather than whatever the caller happened to export, decides the
# downstream's host state; an empty key is never invented because the pinned
# profile decodes hex and refuses "".
#
# The reported state has to agree with the configuration. A campaign that needs
# the durable recovery path must not start against a downstream that will
# refuse every frame, and a sideband that was configured but not reported means
# the operator binary predates the sideband. Only a downstream that reports no
# state at all (an older operator binary) is tolerated, and only when no
# sideband was configured.
#
# The downstream log is appended across restarts (so an archive can rotate it),
# so readiness is judged only on lines written after this launch.
start_mod() {
    [ -f "$mod_log" ] || : > "$mod_log"
    mod_log_offset=$(wc -l < "$mod_log")
    if [ -n "${STS2_SYNTHETIC_HOST_LEASE_KEY:-}" ]; then
        expected_host_lease=enabled
        export STS2_SYNTHETIC_HOST_LEASE_KEY
        if [ -n "${STS2_SYNTHETIC_HOST_PRINCIPAL_ID:-}" ]; then
            export STS2_SYNTHETIC_HOST_PRINCIPAL_ID
        fi
    else
        expected_host_lease=closed
    fi
    STS2_SYNTHETIC_MOD_ADDR=$mod_addr "$bin_dir/synthetic_mod_server" \
        --ignored --exact run_synthetic_downstream_until_terminated --nocapture >> "$mod_log" 2>&1 &
    mod_pid=$!
    tries=0
    while [ "$tries" -lt 50 ]; do
        readiness=$(tail -n +"$((mod_log_offset + 1))" "$mod_log" 2>/dev/null |
            grep synthetic_mod_listening | tail -n 1)
        if [ -n "$readiness" ]; then
            case "$readiness" in
                *"host_lease=$expected_host_lease"*) return 0 ;;
            esac
            if [ "$expected_host_lease" = closed ] &&
                [ "${readiness#*host_lease=}" = "$readiness" ]; then
                return 0
            fi
            printf '%s\n' \
                "the synthetic downstream readiness disagrees with the campaign environment (want host_lease=$expected_host_lease): $readiness" >&2
            return 1
        fi
        sleep 0.2
        tries=$((tries + 1))
    done
    if [ "$expected_host_lease" = enabled ]; then
        printf '%s\n' \
            "the synthetic downstream never reported readiness; when STS2_SYNTHETIC_HOST_LEASE_KEY is set it must be 64 hex characters, because the pinned host terminal refuses every other encoding" >&2
    fi
    return 1
}

restart_mod() {
    kill "$mod_pid" 2>/dev/null || true
    wait "$mod_pid" 2>/dev/null || true
    start_mod
}

gateway_alive() {
    [ -n "${gateway_pid:-}" ] && kill -0 "$gateway_pid" 2>/dev/null
}

# The single deployment is the invariant of --single-deployment: a fault that
# leaves the gateway process dead is not recovered, whatever else happened.
deployment_intact() {
    [ "$single_deployment" -eq 0 ] || gateway_alive
}

start_gateway() {
    STS2_GATEWAY_ADDR=$gateway_addr STS2_MOD_ADDR=$mod_addr STS2_GATEWAY_TOKEN=gateway-token \
        STS2_MOD_TOKEN=mod-token STS2_INSTANCE_ID="${STS2_INSTANCE_ID:-instance-1}" \
        STS2_CALLER_ID="${STS2_CALLER_ID:-harness}" \
        STS2_SESSION_ID="${STS2_SESSION_ID:-gateway-session-1}" STS2_MCP_SESSION_ID=mcp-session-1 \
        STS2_LEASE_ID=lease-1 STS2_LEASE_EPOCH=1 \
        "$bin_dir/sts2-gateway-runtime" >> "$gateway_log" 2>&1 &
    gateway_pid=$!
    sleep 1
}

record_fault() {
    kind=$1 outcome=$2 detail=$3
    if [ -n "$detail" ]; then
        printf '{"ts":"%s","fault":"%s","result":"%s","detail":"%s"}\n' \
            "$(now_iso)" "$kind" "$outcome" "$detail" >> "$results_file"
    else
        printf '{"ts":"%s","fault":"%s","result":"%s"}\n' \
            "$(now_iso)" "$kind" "$outcome" >> "$results_file"
    fi
}

# restart: the supervised synthetic downstream is killed and restarted on the
# same address; recovered when it listens again and the deployment is intact.
inject_restart() {
    kind=$1
    if restart_mod && deployment_intact; then outcome=recovered; else outcome=failed; fi
    record_fault "$kind" "$outcome" ""
}

# archive: copy-truncate the long-lived logs and move completed execution stores
# into a numbered archive directory while the gateway keeps running; recovered
# when the archive holds both logs and the deployment is intact.
archive_seq=0
inject_archive() {
    archive_seq=$((archive_seq + 1))
    target=$archive_dir/$(printf '%06d' "$archive_seq")
    mkdir -p "$target"
    outcome=failed
    if cp "$mod_log" "$target/synthetic-mod.log" 2>/dev/null && : > "$mod_log" \
        && { [ "$single_deployment" -eq 0 ] || { cp "$gateway_log" "$target/gateway.log" && : > "$gateway_log"; }; }; then
        find "$results" -maxdepth 1 -type f -name 'execution-*.sqlite3*' -exec mv -f {} "$target/" \;
        if deployment_intact; then outcome=recovered; fi
    fi
    record_fault archive "$outcome" "archive/$(printf '%06d' "$archive_seq")"
}

# budget: a burst of consecutive downstream restarts, exceeding a one-restart
# budget inside the interval; recovered only when every restart in the burst
# comes back and the deployment is intact.
inject_budget() {
    burst=0
    outcome=recovered
    while [ "$burst" -lt "$budget_burst" ]; do
        burst=$((burst + 1))
        if ! restart_mod; then outcome=failed; break; fi
    done
    deployment_intact || outcome=failed
    record_fault budget "$outcome" "restarts=$burst"
}

# telemetry_outage: no collector listens on the harness's fixed loopback OTLP
# endpoint (127.0.0.1:14318), so the next episode must complete while its own
# telemetry export reports a partial outcome. The fault is recorded after that
# episode; an export that did not observe the outage is a failed injection.
telemetry_outage_pending=0
check_telemetry_outage() {
    log=$1 episode_outcome=$2
    telemetry_outage_pending=0
    if [ "$episode_outcome" = pass ] && grep -q 'telemetry export status=partial' "$log" && deployment_intact; then
        record_fault telemetry_outage recovered "iteration=$iterations"
    else
        record_fault telemetry_outage failed "iteration=$iterations"
    fi
}

inject_fault() {
    case "$1" in
        downstream_restart|restart) inject_restart "$1" ;;
        archive) inject_archive ;;
        budget) inject_budget ;;
        telemetry_outage) telemetry_outage_pending=1 ;;
    esac
}

# Round-robin selection; the caller advances fault_index because a command
# substitution runs in a subshell and would lose the increment.
fault_kind_at() {
    index=$1
    set -- $fault_list
    shift $(( (index - 1) % $# ))
    printf '%s' "$1"
}

start_mod || { printf '%s\n' 'synthetic downstream failed to start' >&2; exit 69; }
gateway_pid=
gateway_log=
if [ "$single_deployment" -eq 1 ]; then
    gateway_addr="127.0.0.1:$gateway_port_base"
    gateway_log=$results/gateway.log
    : > "$gateway_log"
    start_gateway
    gateway_alive || { printf '%s\n' 'single-deployment gateway failed to start' >&2; exit 69; }
    printf '{"ts":"%s","mode":"single-deployment","gateway_addr":"%s","episode_profile":"repeated-episode-lease-v1"}\n' \
        "$(now_iso)" "$gateway_addr" >> "$results_file"
    # A configured host lease key means the window runs on the durable recovery
    # path, which the repeated-episode profile negotiates and which refuses
    # every allocate until the deployment holds an accepted host fence.
    if [ -n "${STS2_RUNTIME_HOST_LEASE_KEY:-}" ]; then
        bringup_durable_recovery
    fi
fi
end=$(( $(date +%s) + duration ))
next_fault=$(( $(date +%s) + fault_interval ))
iterations=0
fault_index=0
while [ "$(date +%s)" -lt "$end" ]; do
    if [ "$(date +%s)" -ge "$next_fault" ]; then
        fault_index=$((fault_index + 1))
        inject_fault "$(fault_kind_at "$fault_index")"
        next_fault=$(( $(date +%s) + fault_interval ))
    fi
    iterations=$((iterations + 1))
    if [ "$single_deployment" -eq 1 ]; then
        # One deployment for the whole window: the gateway is never restarted.
        # A dead gateway ends the campaign as a failed iteration rather than
        # silently composing a second deployment.
        if ! gateway_alive; then
            printf '{"ts":"%s","iteration":%d,"result":"fail","lease_epoch":%d,"gateway_exited":true}\n' \
                "$(now_iso)" "$iterations" "$iterations" >> "$results_file"
            break
        fi
        lease_id="lease-$iterations"
        lease_epoch=$iterations
        episode_profile=true
        runtime_log=$results/.runtime-$iterations.log
    else
        gateway_addr="127.0.0.1:$((gateway_port_base + (iterations % 400)))"
        gateway_log=$results/.gateway-$iterations.log
        : > "$gateway_log"
        start_gateway
        lease_id=lease-1
        lease_epoch=1
        episode_profile=false
        runtime_log=$results/.runtime-$iterations.log
    fi
    runtime_exit=0
    STS2_EXECUTION_STORE_PATH="$results/execution-$iterations.sqlite3" \
        STS2_GATEWAY_ADDR=$gateway_addr STS2_GATEWAY_TOKEN=gateway-token \
        STS2_MCP_BINARY="$bin_dir/sts2-mcp-server" STS2_RUNTIME_PROFILE=runtime-v4-expert \
        STS2_INSTANCE_ID="${STS2_INSTANCE_ID:-instance-1}" STS2_CALLER_ID="${STS2_CALLER_ID:-harness}" \
        STS2_SESSION_ID="${STS2_SESSION_ID:-gateway-session-1}" \
        STS2_MCP_SESSION_ID=mcp-session-1 STS2_LEASE_ID=$lease_id STS2_LEASE_EPOCH=$lease_epoch \
        STS2_EPISODE_PROFILE=$episode_profile \
        STS2_RUN_ID="run-$iterations" STS2_EPISODE_ID="episode-$iterations" \
        STS2_TRAJECTORY_ID="trajectory-$iterations" STS2_TRACE_ID="trace-$iterations" \
        STS2_ARTIFACT_ID="artifact-$iterations" \
        STS2_EXO_REVISION=$exo_revision STS2_EXO_ADMISSION=legacy STS2_PROVIDER_KIND=synthetic \
        STS2_EXO_BRIDGE_BINARY="$bin_dir/bridge.sh" STS2_EXO_TIMEOUT_MILLIS=2000 \
        STS2_EXO_MAX_REQUEST_BYTES=131072 STS2_EXO_MAX_RESPONSE_BYTES=8192 STS2_MAX_STEPS=4 \
        STS2_BARRIER_MAX_POLLS=1 STS2_BARRIER_WAIT_MILLIS=1 STS2_RECOVERY_MAX_ATTEMPTS=2 \
        STS2_RUNTIME_WAIT_FOR_COMBAT_SECONDS=0 STS2_RUNTIME_SETTLEMENT_TIMEOUT_SECONDS=1 \
        STS2_OBJECTIVE="reach the bounded synthetic terminal state" \
        timeout 30 "$bin_dir/sts2-harness-runtime" > "$runtime_log" 2>&1 || runtime_exit=$?
    if [ "$runtime_exit" -eq 0 ]; then
        outcome=pass
    else
        outcome=fail
    fi
    if [ "$single_deployment" -eq 0 ]; then
        kill "$gateway_pid" 2>/dev/null || true
        wait "$gateway_pid" 2>/dev/null || true
    fi
    if [ "$single_deployment" -eq 1 ]; then
        lease_json=$(printf ',"lease_epoch":%d' "$lease_epoch")
    else
        lease_json=
    fi
    if [ "$outcome" = pass ]; then
        printf '{"ts":"%s","iteration":%d,"result":"pass"%s}\n' \
            "$(now_iso)" "$iterations" "$lease_json" >> "$results_file"
        if [ "$telemetry_outage_pending" -eq 1 ]; then check_telemetry_outage "$runtime_log" pass; fi
        rm -f "$runtime_log"
        [ "$single_deployment" -eq 1 ] || rm -f "$gateway_log"
        trim_execution_stores
    else
        retained_gateway=$diagnostics_dir/failure-$iterations.gateway.log
        retained_runtime=$diagnostics_dir/failure-$iterations.runtime.log
        retained_execution=$diagnostics_dir/failure-$iterations.execution.sqlite3
        execution_store_json=null
        if [ "$single_deployment" -eq 1 ]; then
            # The gateway log belongs to the whole deployment; keep a snapshot
            # of its tail for this failure without disturbing the live file.
            tail -n 200 "$gateway_log" > "$retained_gateway"
        else
            mv "$gateway_log" "$retained_gateway"
        fi
        mv "$runtime_log" "$retained_runtime"
        if [ -f "$results/execution-$iterations.sqlite3" ]; then
            mv "$results/execution-$iterations.sqlite3" "$retained_execution"
            execution_store_json=$(printf '"failure-diagnostics/failure-%d.execution.sqlite3"' "$iterations")
        fi
        trim_failure_diagnostics
        printf '{"ts":"%s","iteration":%d,"result":"fail","runtime_exit":%d,"gateway_log":"failure-diagnostics/failure-%d.gateway.log","runtime_log":"failure-diagnostics/failure-%d.runtime.log","execution_store":%s%s}\n' \
            "$(now_iso)" "$iterations" "$runtime_exit" "$iterations" "$iterations" "$execution_store_json" "$lease_json" >> "$results_file"
        if [ "$telemetry_outage_pending" -eq 1 ]; then check_telemetry_outage "$retained_runtime" fail; fi
    fi
    sleep 4
done
if [ "$single_deployment" -eq 1 ]; then
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
fi
kill "$mod_pid" 2>/dev/null || true
wait "$mod_pid" 2>/dev/null || true
printf '{"ts":"%s","done":true,"iterations":%d}\n' "$(now_iso)" "$iterations" >> "$results_file"

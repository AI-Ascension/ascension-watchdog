#!/bin/sh
# Reproducible cross-repo campaign runner.
#
# Keeps one synthetic downstream (the sts2-harness operator test server) running
# for the whole campaign while the gateway + MCP + harness stack runs one
# episode per iteration, and periodically restarts the downstream as a fault.
# Records {"ts","iteration","result"} and {"ts","fault","result"} lines. Each
# failed iteration retains a bounded runtime/gateway log pair and records their
# relative paths and runtime exit status. Each iteration uses a fresh gateway
# because the current companion contract admits one episode per gateway instance.
#
# Usage:
#   crossrepo-campaign.sh --bin-dir DIR --results PATH --duration-seconds N \
#     [--fault-interval-seconds N] [--max-failure-diagnostics N] \
#     [--mod-addr ADDR] [--gateway-port-base N]
set -eu

usage() {
    printf '%s\n' 'usage: crossrepo-campaign.sh --bin-dir DIR --results PATH --duration-seconds N [--fault-interval-seconds N] [--max-failure-diagnostics N] [--mod-addr ADDR] [--gateway-port-base N]' >&2
    exit 64
}

bin_dir=
results=
duration=
fault_interval=900
max_failure_diagnostics=16
mod_addr=127.0.0.1:20001
gateway_port_base=21000
while [ "$#" -gt 0 ]; do
    case "$1" in
        --bin-dir) [ "$#" -ge 2 ] || usage; bin_dir=$2; shift 2 ;;
        --results) [ "$#" -ge 2 ] || usage; results=$2; shift 2 ;;
        --duration-seconds) [ "$#" -ge 2 ] || usage; duration=$2; shift 2 ;;
        --fault-interval-seconds) [ "$#" -ge 2 ] || usage; fault_interval=$2; shift 2 ;;
        --max-failure-diagnostics) [ "$#" -ge 2 ] || usage; max_failure_diagnostics=$2; shift 2 ;;
        --mod-addr) [ "$#" -ge 2 ] || usage; mod_addr=$2; shift 2 ;;
        --gateway-port-base) [ "$#" -ge 2 ] || usage; gateway_port_base=$2; shift 2 ;;
        *) usage ;;
    esac
done
[ -n "$bin_dir" ] && [ -n "$results" ] && [ -n "$duration" ] || usage
case "$max_failure_diagnostics" in
    ''|*[!0-9]*) usage ;;
esac
[ "$max_failure_diagnostics" -gt 0 ] || usage

for name in synthetic_mod_server sts2-gateway-runtime sts2-harness-runtime sts2-mcp-server bridge.sh; do
    [ -e "$bin_dir/$name" ] || { printf '%s\n' "missing campaign input: $bin_dir/$name" >&2; exit 66; }
done
mkdir -p "$results"
results_file=$results/iterations.jsonl
diagnostics_dir=$results/failure-diagnostics
mod_log=$results/synthetic-mod.log
mkdir -p "$diagnostics_dir"
: > "$results_file"

trim_failure_diagnostics() {
    retained=$(find "$diagnostics_dir" -maxdepth 1 -type f -name 'failure-*.runtime.log' | wc -l)
    while [ "$retained" -gt "$max_failure_diagnostics" ]; do
        oldest=$(find "$diagnostics_dir" -maxdepth 1 -type f -name 'failure-*.runtime.log' | sort | head -n 1)
        [ -n "$oldest" ] || return 0
        base=${oldest%.runtime.log}
        rm -f "$oldest" "$base.gateway.log"
        retained=$((retained - 1))
    done
}

start_mod() {
    STS2_SYNTHETIC_MOD_ADDR=$mod_addr "$bin_dir/synthetic_mod_server" \
        --ignored --exact run_synthetic_downstream_until_terminated --nocapture > "$mod_log" 2>&1 &
    mod_pid=$!
    tries=0
    while [ "$tries" -lt 50 ]; do
        if grep -q synthetic_mod_listening "$mod_log" 2>/dev/null; then return 0; fi
        sleep 0.2
        tries=$((tries + 1))
    done
    return 1
}

start_mod || { printf '%s\n' 'synthetic downstream failed to start' >&2; exit 69; }
end=$(( $(date +%s) + duration ))
next_fault=$(( $(date +%s) + fault_interval ))
iterations=0
while [ "$(date +%s)" -lt "$end" ]; do
    if [ "$(date +%s)" -ge "$next_fault" ]; then
        kill "$mod_pid" 2>/dev/null || true
        wait "$mod_pid" 2>/dev/null || true
        if start_mod; then outcome=recovered; else outcome=failed; fi
        printf '{"ts":"%s","fault":"downstream_restart","result":"%s"}\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$outcome" >> "$results_file"
        next_fault=$(( $(date +%s) + fault_interval ))
    fi
    iterations=$((iterations + 1))
    gateway_addr="127.0.0.1:$((gateway_port_base + (iterations % 400)))"
    gateway_log=$results/.gateway-$iterations.log
    runtime_log=$results/.runtime-$iterations.log
    STS2_GATEWAY_ADDR=$gateway_addr STS2_MOD_ADDR=$mod_addr STS2_GATEWAY_TOKEN=gateway-token \
        STS2_MOD_TOKEN=mod-token STS2_INSTANCE_ID=instance-1 STS2_CALLER_ID=harness \
        STS2_SESSION_ID=gateway-session-1 STS2_MCP_SESSION_ID=mcp-session-1 \
        STS2_LEASE_ID=lease-1 STS2_LEASE_EPOCH=1 \
        "$bin_dir/sts2-gateway-runtime" > "$gateway_log" 2>&1 &
    gateway_pid=$!
    sleep 1
    runtime_exit=0
    STS2_EXECUTION_STORE_PATH="$results/execution-$iterations.sqlite3" \
        STS2_GATEWAY_ADDR=$gateway_addr STS2_GATEWAY_TOKEN=gateway-token \
        STS2_MCP_BINARY="$bin_dir/sts2-mcp-server" STS2_RUNTIME_PROFILE=runtime-v4-expert \
        STS2_INSTANCE_ID=instance-1 STS2_CALLER_ID=harness STS2_SESSION_ID=gateway-session-1 \
        STS2_MCP_SESSION_ID=mcp-session-1 STS2_LEASE_ID=lease-1 STS2_LEASE_EPOCH=1 \
        STS2_RUN_ID="run-$iterations" STS2_EPISODE_ID="episode-$iterations" \
        STS2_TRAJECTORY_ID="trajectory-$iterations" STS2_TRACE_ID="trace-$iterations" \
        STS2_ARTIFACT_ID="artifact-$iterations" \
        STS2_EXO_REVISION=7801005e6a1ab77008a05dbba80e0a2a7a56e35d STS2_PROVIDER_KIND=synthetic \
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
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
    if [ "$outcome" = pass ]; then
        rm -f "$gateway_log" "$runtime_log"
        printf '{"ts":"%s","iteration":%d,"result":"pass"}\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$iterations" >> "$results_file"
    else
        retained_gateway=$diagnostics_dir/failure-$iterations.gateway.log
        retained_runtime=$diagnostics_dir/failure-$iterations.runtime.log
        mv "$gateway_log" "$retained_gateway"
        mv "$runtime_log" "$retained_runtime"
        trim_failure_diagnostics
        printf '{"ts":"%s","iteration":%d,"result":"fail","runtime_exit":%d,"gateway_log":"failure-diagnostics/failure-%d.gateway.log","runtime_log":"failure-diagnostics/failure-%d.runtime.log"}\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$iterations" "$runtime_exit" "$iterations" "$iterations" >> "$results_file"
    fi
    sleep 4
done
kill "$mod_pid" 2>/dev/null || true
wait "$mod_pid" 2>/dev/null || true
printf '{"ts":"%s","done":true,"iterations":%d}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$iterations" >> "$results_file"

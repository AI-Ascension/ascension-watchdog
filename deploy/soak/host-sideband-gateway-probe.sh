#!/bin/sh
# Operator-only cross-process probe for the downstream host sideband
# (ascension-watchdog#58).
#
# The campaign scripts prove, in CI, that `crossrepo-campaign.sh` composes the
# sideband and refuses a downstream whose readiness disagrees. This probe goes
# one level deeper and cannot run in CI: it points a real `sts2-gateway-runtime`
# process at a real `synthetic_mod_server` process over loopback and drives the
# recovery routes, so the assertions are made by the *served* gateway and the
# *served* downstream rather than by a library call or a stub.
#
# It requires both binaries to be built from the pinned revisions first. It
# changes nothing outside its own temporary directory. It is not soak evidence.
#
# Usage:
#   sh deploy/soak/host-sideband-gateway-probe.sh \
#       --gateway-bin /path/to/sts2-gateway-runtime \
#       --mod-bin /path/to/synthetic_mod_server \
#       --mode configured|wrong-key|closed
#
# Exit status: 0 when the mode's expectation held, 1 when it did not, 69 when
# the downstream reported a sideband state other than the requested one.

set -eu

GATEWAY_BIN=""
MOD_BIN=""
MODE="configured"

usage() {
    sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --gateway-bin) GATEWAY_BIN=${2:-}; shift 2 ;;
        --mod-bin) MOD_BIN=${2:-}; shift 2 ;;
        --mode) MODE=${2:-}; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

for required in GATEWAY_BIN MOD_BIN; do
    eval "value=\${$required}"
    if [ -z "$value" ] || [ ! -x "$value" ]; then
        echo "$required must name an executable binary" >&2
        exit 2
    fi
done

case "$MODE" in
    configured|wrong-key|closed) ;;
    *) echo "unknown mode: $MODE" >&2; exit 2 ;;
esac

# The host lease-control key is bytes 0x00..=0x1f, written as 64 hex characters.
# The harness terminal only accepts hex; the gateway accepts hex or base64, so
# the shared value is hex. The foreign key is the same shape with other bytes.
HOST_LEASE_KEY_HEX="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
FOREIGN_LEASE_KEY_HEX="202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
# Bootstrap secret: bytes 0x10..=0x2f, base64, which is what the gateway expects.
BOOTSTRAP_SECRET_B64="EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8="

DEPLOYMENT="00000000-0000-4000-8000-000000000001"
INSTANCE="00000000-0000-4000-8000-000000000002"
INCARNATION="00000000-0000-4000-8000-000000000003"
CALLER="00000000-0000-4000-8000-00000000000a"
SESSION="00000000-0000-4000-8000-00000000000b"
MCP_SESSION="00000000-0000-4000-8000-00000000000c"
ATTACHED_LEASE="00000000-0000-4000-8000-00000000000d"
HOST_PRINCIPAL="00000000-0000-4000-8000-00000000000e"

GATEWAY_TOKEN="gateway-token"
RECOVERY_TOKEN="recovery-token"
MOD_TOKEN="mod-token"

RECOVERY_CONTRACT="watchdog-recovery-v1"
RECOVERY_SCHEMA_DIGEST="fb934d3157485aaf6e13e6ebbb213ec8a14c7fc6f5eeebc06b7a22c1f0009217"
RUNTIME_V3_SCHEMA_DIGEST="8e99cea36b7ede97532348fd8efe302ca79260895265a7bf14ddf7e006d8ff63"
ZERO_DIGEST="0000000000000000000000000000000000000000000000000000000000000000"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/sts2-host-sideband-probe-XXXXXX")
mod_log="$scratch/mod.log"
gateway_log="$scratch/gateway.log"
store="$scratch/recovery.db"
mod_pid=""
gateway_pid=""

cleanup() {
    for pid in $gateway_pid $mod_pid; do
        [ -n "$pid" ] || continue
        kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    find "$scratch" -mindepth 1 -delete 2>/dev/null || true
    rmdir "$scratch" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

gateway_port=$(( ( $(date +%N | cut -c1-5) % 20000 ) + 20000 ))

# One frame per call, with fresh uuid-v4 message and correlation identities.
frame() {
    kind=$1 capability=$2 payload=$3
    message_id=$(cat /proc/sys/kernel/random/uuid)
    correlation_id=$(cat /proc/sys/kernel/random/uuid)
    sent_at=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)
    jq -cn \
        --arg contract "$RECOVERY_CONTRACT" \
        --arg schema "$RECOVERY_SCHEMA_DIGEST" \
        --arg message "$message_id" \
        --arg correlation "$correlation_id" \
        --arg sent_at "$sent_at" \
        --arg principal "$CALLER" \
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
    path=$1 capability=$2 body=$3
    curl -sS -o "$scratch/body.json" -w '%{http_code}' \
        -H "Authorization: Bearer $RECOVERY_TOKEN" \
        -H "Content-Type: application/json" \
        -H "x-sts2-recovery-capability: $capability" \
        -H 'User-Agent:' -H 'Accept:' \
        --data-binary "$body" \
        "http://127.0.0.1:$gateway_port$path"
}

live_status() {
    curl -sS -o /dev/null -w '%{http_code}' \
        -H "Authorization: Bearer $GATEWAY_TOKEN" \
        -H 'User-Agent:' -H 'Accept:' \
        "http://127.0.0.1:$gateway_port/health/live" 2>/dev/null || echo 000
}

echo "[$MODE] starting the synthetic downstream"
# `env -i` keeps ambient STS2_* configuration out of both children: an inherited
# key would silently satisfy the `closed` control, which is the whole point.
set -- \
    env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" \
    STS2_SYNTHETIC_MOD_ADDR=127.0.0.1:0 \
    STS2_SYNTHETIC_MOD_MODE=success
case "$MODE" in
    configured) set -- "$@" "STS2_SYNTHETIC_HOST_LEASE_KEY=$HOST_LEASE_KEY_HEX" "STS2_SYNTHETIC_HOST_PRINCIPAL_ID=$HOST_PRINCIPAL" ;;
    wrong-key) set -- "$@" "STS2_SYNTHETIC_HOST_LEASE_KEY=$FOREIGN_LEASE_KEY_HEX" "STS2_SYNTHETIC_HOST_PRINCIPAL_ID=$HOST_PRINCIPAL" ;;
    closed) ;;
esac
"$@" "$MOD_BIN" --ignored --exact run_synthetic_downstream_until_terminated --nocapture \
    >"$mod_log" 2>&1 &
mod_pid=$!

attempt=0
ready_line=""
while [ "$attempt" -lt 400 ]; do
    ready_line=$(grep -m1 'synthetic_mod_listening=' "$mod_log" 2>/dev/null || true)
    [ -n "$ready_line" ] && break
    attempt=$((attempt + 1))
    sleep 0.05
done
echo "[$MODE] downstream readiness: ${ready_line:-<none>}"
if [ -z "$ready_line" ]; then
    echo "FAIL: the downstream never reported readiness" >&2
    tail -20 "$mod_log" >&2
    exit 1
fi

mod_address=$(printf '%s' "$ready_line" | sed -n 's/.*synthetic_mod_listening=\([0-9.:]*\).*/\1/p')
if [ -z "$mod_address" ]; then
    echo "FAIL: the readiness line carried no address" >&2
    exit 1
fi

if [ "$MODE" = "closed" ]; then
    expected="host_lease=closed"
else
    expected="host_lease=enabled"
fi
if ! printf '%s' "$ready_line" | grep -q "$expected"; then
    echo "FAIL: the downstream reported no $expected; refusing to start" >&2
    exit 69
fi

echo "[$MODE] starting the gateway against $mod_address"
env -i PATH=/usr/bin:/bin HOME="${HOME:-/root}" \
    STS2_GATEWAY_ADDR="127.0.0.1:$gateway_port" \
    STS2_MOD_ADDR="$mod_address" \
    STS2_GATEWAY_TOKEN="$GATEWAY_TOKEN" \
    STS2_RECOVERY_TOKEN="$RECOVERY_TOKEN" \
    STS2_MOD_TOKEN="$MOD_TOKEN" \
    STS2_INSTANCE_ID="$INSTANCE" \
    STS2_CALLER_ID="$CALLER" \
    STS2_SESSION_ID="$SESSION" \
    STS2_MCP_SESSION_ID="$MCP_SESSION" \
    STS2_LEASE_ID="$ATTACHED_LEASE" \
    STS2_LEASE_EPOCH=1 \
    STS2_DEPLOYMENT_ID="$DEPLOYMENT" \
    STS2_RECOVERY_STORE="$store" \
    STS2_RUNTIME_HOST_PRINCIPAL_ID="$HOST_PRINCIPAL" \
    STS2_RUNTIME_HOST_LEASE_KEY="$HOST_LEASE_KEY_HEX" \
    STS2_RUNTIME_BOOTSTRAP_SECRET="$BOOTSTRAP_SECRET_B64" \
    "$GATEWAY_BIN" >"$gateway_log" 2>&1 &
gateway_pid=$!

attempt=0
while [ "$attempt" -lt 400 ]; do
    [ "$(live_status)" = "200" ] && break
    attempt=$((attempt + 1))
    sleep 0.05
done
if [ "$(live_status)" != "200" ]; then
    echo "FAIL: the gateway never served /health/live" >&2
    tail -20 "$gateway_log" >&2
    exit 1
fi

bootstrap_payload=$(jq -cn \
    --arg deployment "$DEPLOYMENT" --arg instance "$INSTANCE" --arg incarnation "$INCARNATION" \
    --arg release_digest "$ZERO_DIGEST" --arg config_digest "$ZERO_DIGEST" \
    --arg profile_digest "$ZERO_DIGEST" --arg schema "$RUNTIME_V3_SCHEMA_DIGEST" \
    '{deployment_id:$deployment, instance_id:$instance, instance_incarnation:$incarnation,
      release:{release_digest:$release_digest, config_digest:$config_digest,
               profile_digest:$profile_digest, runtime_v3_schema_digest:$schema},
      lease_policy:{ttl_seconds:30, renewal_interval_seconds:10}}')

status=$(recovery_post /v1/recovery/bootstrap bootstrap "$(frame bootstrap_request bootstrap "$bootstrap_payload")")
echo "[$MODE] bootstrap -> $status $(jq -c '.payload//.error_code//.' "$scratch/body.json")"
if [ "$status" != "200" ]; then
    echo "FAIL: bootstrap was refused" >&2
    exit 1
fi
boot=$(jq -c '.payload.boot' "$scratch/body.json")

status=$(recovery_post /v1/recovery/host-fence host_fence "$(frame host_fence_request host_fence "$(jq -cn --argjson boot "$boot" '{boot:$boot}')")")
fence_status=$(jq -r '.payload.result.status // .error_code // "?"' "$scratch/body.json")
echo "[$MODE] host-fence -> $status $fence_status"

if [ "$MODE" = "closed" ]; then
    if [ "$status" = "200" ] && [ "$fence_status" = "FENCE_ACCEPTED" ]; then
        echo "FAIL: the fence succeeded with the downstream sideband removed" >&2
        exit 1
    fi
    echo "[$MODE] PASS: the fence failed closed with the downstream sideband removed"
    exit 0
fi

if [ "$status" != "200" ] || [ "$fence_status" != "FENCE_ACCEPTED" ]; then
    echo "FAIL: the fence was refused" >&2
    tail -20 "$gateway_log" >&2
    exit 1
fi
# The acknowledgment must be bound to the boot the served gateway presented.
fence=$(jq -c '.payload.fence' "$scratch/body.json")
mismatch=$(jq -rn \
    --argjson fence "$fence" --argjson boot "$boot" \
    '["deployment_id","instance_id","instance_incarnation","boot_id","authority_generation"]
     | map(select(($fence[.]|tostring) != ($boot[.]|tostring)))
     | join(",")')
if [ -n "$mismatch" ]; then
    echo "FAIL: the fence is not bound to the served boot ($mismatch)" >&2
    exit 1
fi
echo "[$MODE] the fence is accepted and bound to the served boot"

# The durable transition is authoritative, so the boot to present for
# acquisition is READY even though bootstrap reported FENCE_REQUIRED.
boot_ready=$(printf '%s' "$boot" | jq -c '.state="READY"')
acquire_payload=$(jq -cn --argjson boot "$boot_ready" --argjson fence "$fence" '{boot:$boot, fence:$fence}')
status=$(recovery_post /v1/recovery/lease/acquire lease_acquire "$(frame lease_acquire_request lease_acquire "$acquire_payload")")
echo "[$MODE] lease-acquire -> $status $(jq -c '.payload.result.status // .error_code // "?"' "$scratch/body.json")"

if [ "$MODE" = "wrong-key" ]; then
    if [ "$status" = "200" ]; then
        echo "FAIL: lease acquisition accepted a foreign host-lease proof" >&2
        exit 1
    fi
    echo "[$MODE] PASS: the gateway refused the foreign host-lease acknowledgment proof"
    exit 0
fi

if [ "$status" != "200" ]; then
    echo "FAIL: lease acquisition was refused" >&2
    tail -20 "$gateway_log" >&2
    exit 1
fi
echo "[$MODE] PASS: the fence and the lease install were accepted across the two served processes"

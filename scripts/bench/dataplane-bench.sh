#!/usr/bin/env bash
# dataplane-bench.sh — fair A/B dataplane comparison harness.
#
# Compares two sing-box binaries on the SAME host, SAME node pool and the
# SAME traffic model, so "official TUN/auto_redirect" and this fork's TC
# dataplane can be measured instead of argued about (audit point #28).
#
# Prerequisites on the test host (root):
#   iperf3 (server reachable), curl, jq; root for dataplane restarts.
# Both configs must expose a mixed/socks inbound on $PROXY_PORT and select
# the same upstream node(s). Model selection:
#   TRAFFIC_MODEL=proxy   — all requests through the proxy inbound
#   TRAFFIC_MODEL=direct  — all requests bypass the proxy (DIRECT share)
#
# Usage:
#   sudo TRAFFIC_MODEL=proxy \
#        CANDIDATE_A_NAME=official CANDIDATE_A_BIN=/opt/official/sing-box \
#        CANDIDATE_A_CONF=/opt/official/config.json \
#        CANDIDATE_B_NAME=smart    CANDIDATE_B_BIN=/opt/smart/sing-box \
#        CANDIDATE_B_CONF=/opt/smart/config.json \
#        ROUNDS=3 \
#        ./scripts/bench/dataplane-bench.sh
#
# Output: bench-results/<timestamp>/round-N.{csv,json} + a summary table.
set -euo pipefail

: "${CANDIDATE_A_NAME:=A}"
: "${CANDIDATE_A_BIN:?set CANDIDATE_A_BIN}"
: "${CANDIDATE_A_CONF:?set CANDIDATE_A_CONF}"
: "${CANDIDATE_B_NAME:=B}"
: "${CANDIDATE_B_BIN:?set CANDIDATE_B_BIN}"
: "${CANDIDATE_B_CONF:?set CANDIDATE_B_CONF}"
: "${PROXY_ADDR:=127.0.0.1}"
: "${PROXY_PORT:=8888}"
: "${BENCH_URL:=https://www.gstatic.com/generate_204}"
: "${IPERF_HOST:=${IPERF_HOST:-}}"
: "${IPERF_SECONDS:=10}"
: "${LATENCY_SAMPLES:=100}"
: "${ROUNDS:=2}"
: "${WARMUP_SECONDS:=10}"
: "${TRAFFIC_MODEL:=proxy}"

OUTROOT="bench-results/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTROOT"

start_candidate() { # $1 bin $2 conf -> echoes pid
    "$1" run -c "$2" >/dev/null 2>&1 &
    echo $!
}

stop_candidate() {
    local pid="$1"
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
    kill -9 "$pid" 2>/dev/null || true
}

# cpu_ticks <pid> -> "utime stime" (clock ticks)
cpu_ticks() {
    awk '{print $14, $15}' "/proc/$1/stat" 2>/dev/null || echo "0 0"
}

latency_percentiles() { # writes p50/p95/p99 in ms to stdout
    local samples=()
    for _ in $(seq 1 "$LATENCY_SAMPLES"); do
        local t
        t=$(curl -s -o /dev/null -w '%{time_total}' ${PROXY_FLAGS:-} \
            -x "$PROXY_ADDR:$PROXY_PORT" --max-time 5 "$BENCH_URL" 2>/dev/null || echo 5)
        samples+=("$(awk -v t="$t" 'BEGIN{printf "%.1f", t*1000}')")
    done
    printf '%s\n' "${samples[@]}" | sort -n | awk -v n="${#samples[@]}" '
        {v[NR]=$1}
        END{printf "%.1f %.1f %.1f\n", v[int(n*0.5)], v[int(n*0.95)], v[int(n*0.99)]}'
}

throughput_mbps() { # iperf3 through the proxy inbound; empty if no iperf host
    [ -n "$IPERF_HOST" ] || { echo ""; return; }
    command -v iperf3 >/dev/null || { echo ""; return; }
    iperf3 -4 -n "${IPERF_BYTES:-512M}" -c "$IPERF_HOST" \
        -x scp --socks5 "$PROXY_ADDR:$PROXY_PORT" -J 2>/dev/null \
        | jq -r '.end.sum_received.bits_per_second / 1000000' 2>/dev/null || echo ""
}

run_round() { # $1 candidate-name $2 bin $3 conf $4 round
    local name="$1" bin="$2" conf="$3" round="$4"
    local pid before_u before_s after_u after_s out
    pid=$(start_candidate "$bin" "$conf")
    sleep "$WARMUP_SECONDS"
    read -r before_u before_s <<< "$(cpu_ticks "$pid")"

    local lat mbps
    lat=$(latency_percentiles)
    mbps=$(throughput_mbps)

    read -r after_u after_s <<< "$(cpu_ticks "$pid")"
    local window=8  # approx measured CPU window (latency+throughput), seconds
    local cpu_pct
    cpu_pct=$(awk -v u="$((after_u-before_u))" -v s="$((after_s-before_s))" \
        -v w="$window" 'BEGIN{printf "%.2f", (u+s)/(w*100)*100}')
    stop_candidate "$pid"

    out="$OUTROOT/round-$round.csv"
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$round" "$name" "$TRAFFIC_MODEL" \
        "$LATENCY_SAMPLES" "${lat% *}" "$(echo "$lat" | cut -d' ' -f2)" \
        "$(echo "$lat" | cut -d' ' -f3)" "${cpu_pct}" >> "$out"
    [ -n "$mbps" ] && printf '%s,%s,%s,%s\n' "$round" "$name" "$TRAFFIC_MODEL" "$mbps" \
        >> "$OUTROOT/round-$round-throughput.csv"
}

summary() {
    local f
    echo "==== latency (ms p50/p95/p99) and sing-box CPU%% ===="
    printf '%-6s %-10s %-6s %8s %8s %8s %8s\n' ROUND CANDIDATE MODEL SAMPLES p50 p95 p99 CPU%
    for f in "$OUTROOT"/round-*.csv; do
        [ -f "$f" ] || continue
        tail -n +1 "$f" | while IFS=, read -r r name model samples p50 p95 p99 cpu; do
            printf '%-6s %-10s %-6s %8s %8s %8s %8s\n' "$r" "$name" "$model" "$samples" "$p50" "$p95" "$p99" "$cpu"
        done
    done
    for f in "$OUTROOT"/round-*-throughput.csv; do
        [ -f "$f" ] || continue
        echo "==== throughput (Mbps, iperf3 via proxy) ===="
        cat "$f"
    done
}

echo "model=$TRAFFIC_MODEL rounds=$ROUNDS url=$BENCH_URL proxy=$PROXY_ADDR:$PROXY_PORT"
for round in $(seq 1 "$ROUNDS"); do
    echo "--- round $round: $CANDIDATE_A_NAME ---"
    run_round "$CANDIDATE_A_NAME" "$CANDIDATE_A_BIN" "$CANDIDATE_A_CONF" "$round"
    echo "--- round $round: $CANDIDATE_B_NAME ---"
    run_round "$CANDIDATE_B_NAME" "$CANDIDATE_B_BIN" "$CANDIDATE_B_CONF" "$round"
done
summary | tee "$OUTROOT/summary.txt"
echo "results: $OUTROOT"

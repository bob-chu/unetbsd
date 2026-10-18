#!/usr/bin/env bash
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../../../.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build-dpdk"
LOG_DIR="${SCRIPT_DIR}/logs"
mkdir -p "${LOG_DIR}"

INTERVAL_SECS=$((1 * 3600 + 28 * 60)) # 1h28m = 5280 seconds
RUN_ONCE="${1:-loop}"                 # "once" or "loop" (default: loop every 1h28m)

cleanup() {
    echo "[run_bench] Stopping existing perf_tool instances..."
    pkill -9 perf_tool 2>/dev/null || true
    rm -rf /var/run/dpdk/memif_* /tmp/memif_test4.sock* /run/memif* 2>/dev/null || true
    sleep 1
}

run_iteration() {
    local iter="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local s_log="${LOG_DIR}/server_${iter}_${timestamp}.log"
    local c_log="${LOG_DIR}/client_${iter}_${timestamp}.log"

    echo "=========================================================="
    echo "[run_bench] Starting Iteration #${iter} at $(date)"
    echo "[run_bench] Duration: ${INTERVAL_SECS}s (1h28m)"
    echo "[run_bench] Logs: ${s_log} | ${c_log}"
    echo "=========================================================="

    cleanup

    # 1. Start Server
    "${BUILD_DIR}/perf_tool" server "${SCRIPT_DIR}/s.json" > "${s_log}" 2>&1 &
    local SPID=$!
    echo "[run_bench] Server started (PID: ${SPID})"
    sleep 2

    # 2. Start Client
    "${BUILD_DIR}/perf_tool" client "${SCRIPT_DIR}/c.json" > "${c_log}" 2>&1 &
    local CPID=$!
    echo "[run_bench] Client started (PID: ${CPID})"

    # 3. Stream real-time metrics for 1h28m
    echo "[run_bench] Running for ${INTERVAL_SECS} seconds..."
    local end_time=$(( $(date +%s) + INTERVAL_SECS ))
    while [ $(date +%s) -lt $end_time ]; do
        if ! kill -0 $CPID 2>/dev/null || ! kill -0 $SPID 2>/dev/null; then
            echo "[run_bench] Warning: Process exited prematurely."
            break
        fi
        tail -n 1 "${c_log}" 2>/dev/null | grep -E '(\[client\])' || true
        sleep 5
    done

    echo "[run_bench] Iteration #${iter} finished or deadline reached. Restarting after cleanup..."
    cleanup
}

trap cleanup EXIT INT TERM

iter=1
while true; do
    run_iteration "$iter"
    if [ "${RUN_ONCE}" = "once" ]; then
        echo "[run_bench] Single run completed."
        break
    fi
    iter=$((iter + 1))
done

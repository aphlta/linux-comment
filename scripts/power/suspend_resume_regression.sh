#!/usr/bin/env bash
set -euo pipefail

# Why: suspend issues are probabilistic; only loop tests reveal real failure rate.

OUT_DIR="${1:-suspend_regression_$(date +%Y%m%d_%H%M%S)}"
CYCLES="${2:-50}"
SLEEP_MODE="${3:-mem}"
HOLD_SEC="${4:-10}"

mkdir -p "${OUT_DIR}"
echo "cycle,start_ts,end_ts,resume_latency_ms,result" > "${OUT_DIR}/summary.csv"

for ((i=1; i<=CYCLES; i++)); do
  start_ms="$(date +%s%3N)"
  echo "[INFO] cycle=${i} mode=${SLEEP_MODE}" | tee -a "${OUT_DIR}/run.log"

  # Why: clear short logs before each cycle to isolate failure evidence.
  dmesg -c > "${OUT_DIR}/dmesg_pre_cycle_${i}.log" || true

  if ! sh -c "echo ${SLEEP_MODE} > /sys/power/state"; then
    end_ms="$(date +%s%3N)"
    latency=$((end_ms - start_ms))
    echo "${i},${start_ms},${end_ms},${latency},fail_suspend" >> "${OUT_DIR}/summary.csv"
    dmesg > "${OUT_DIR}/dmesg_fail_cycle_${i}.log" || true
    continue
  fi

  sleep "${HOLD_SEC}"
  end_ms="$(date +%s%3N)"
  latency=$((end_ms - start_ms))
  echo "${i},${start_ms},${end_ms},${latency},ok" >> "${OUT_DIR}/summary.csv"
  dmesg > "${OUT_DIR}/dmesg_cycle_${i}.log" || true
done

echo "[INFO] suspend/resume regression completed: ${OUT_DIR}"

#!/usr/bin/env bash
set -euo pipefail

# Why: runtime PM issues are hidden unless you sample status over time.

OUT_DIR="${1:-runtime_pm_audit_$(date +%Y%m%d_%H%M%S)}"
INTERVAL="${2:-2}"
LOOPS="${3:-120}"

mkdir -p "${OUT_DIR}"
echo "[INFO] Output: ${OUT_DIR}"

mapfile -t DEVICES < <(find /sys/devices -type d -name power 2>/dev/null || true)

if [ "${#DEVICES[@]}" -eq 0 ]; then
  echo "[WARN] no power directories found under /sys/devices"
fi

for ((i=1; i<=LOOPS; i++)); do
  ts="$(date +%s)"
  out="${OUT_DIR}/sample_${i}.csv"
  echo "timestamp,device_path,runtime_status,active_ms,suspended_ms,autosuspend_delay_ms" > "${out}"
  for p in "${DEVICES[@]}"; do
    dev="$(dirname "${p}")"
    status="$(cat "${p}/runtime_status" 2>/dev/null || echo NA)"
    active="$(cat "${p}/runtime_active_time" 2>/dev/null || echo NA)"
    suspended="$(cat "${p}/runtime_suspended_time" 2>/dev/null || echo NA)"
    delay="$(cat "${p}/autosuspend_delay_ms" 2>/dev/null || echo NA)"
    echo "${ts},${dev},${status},${active},${suspended},${delay}" >> "${out}"
  done
  sleep "${INTERVAL}"
done

echo "[INFO] runtime PM audit complete."

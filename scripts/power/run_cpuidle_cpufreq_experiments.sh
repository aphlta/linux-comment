#!/usr/bin/env bash
set -euo pipefail

# Why: controlled A/B runs reduce false conclusions from thermal/noise drift.

OUT_DIR="${1:-cpu_pm_experiments_$(date +%Y%m%d_%H%M%S)}"
RUNTIME="${2:-120}"
GOVERNORS=("schedutil" "performance" "powersave")

mkdir -p "${OUT_DIR}"

if [ ! -d /sys/devices/system/cpu/cpufreq ]; then
  echo "[ERROR] cpufreq sysfs not found."
  exit 1
fi

POLICY_GLOB="/sys/devices/system/cpu/cpufreq/policy*"
echo "[INFO] Output: ${OUT_DIR}" | tee "${OUT_DIR}/run.log"

set_governor() {
  local gov="$1"
  for p in ${POLICY_GLOB}; do
    if [ -w "${p}/scaling_governor" ]; then
      echo "${gov}" > "${p}/scaling_governor" || true
    fi
  done
}

capture_snapshot() {
  local tag="$1"
  mkdir -p "${OUT_DIR}/${tag}"
  for p in ${POLICY_GLOB}; do
    [ -f "${p}/scaling_governor" ] && cat "${p}/scaling_governor" >> "${OUT_DIR}/${tag}/governors.txt" || true
    [ -f "${p}/scaling_cur_freq" ] && cat "${p}/scaling_cur_freq" >> "${OUT_DIR}/${tag}/cur_freq.txt" || true
  done
  if [ -f /sys/kernel/debug/wakeup_sources ]; then
    cat /sys/kernel/debug/wakeup_sources > "${OUT_DIR}/${tag}/wakeup_sources.txt" || true
  fi
}

run_idle_case() {
  local gov="$1"
  local case_dir="${OUT_DIR}/idle_${gov}"
  mkdir -p "${case_dir}"
  echo "[INFO] Running idle case governor=${gov}" | tee -a "${OUT_DIR}/run.log"
  set_governor "${gov}"
  capture_snapshot "before_${gov}"
  sleep "${RUNTIME}"
  capture_snapshot "after_${gov}"
}

for gov in "${GOVERNORS[@]}"; do
  run_idle_case "${gov}"
done

echo "[INFO] CPU PM experiments completed."
